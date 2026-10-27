//! The `t3_*` tool contract for ChatGPT, mapped onto T3 Code's own MCP tools.
//!
//! Every handler first resolves the target session through T3 and checks it against
//! the caller's grant. Business rules (queueing, idempotent commands, runtime-mode
//! ceilings, approvals) remain T3's; this layer adds scoping, stable run lookup and
//! normalized states.
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Map, Value, json};
use std::time::Duration;

use super::store::{Access, GatewayStore, Grant, RunRecord, sha256_b64};
use super::upstream::{ToolFailure, Upstream};

const READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WAIT_SECONDS: u64 = 50;
const MAX_MESSAGE_CHARS: usize = 100_000;
const RESULT_SCAN_PAGES: usize = 40;

/// A failure reported to the MCP client as a tool error, never as a transport error.
#[derive(Debug)]
pub struct Denied(pub &'static str, pub String);
impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}
impl std::error::Error for Denied {}

fn denied(code: &'static str, message: impl Into<String>) -> anyhow::Error {
    anyhow!(Denied(code, message.into()))
}

pub struct ToolContext<'a> {
    pub grant: &'a Grant,
    pub store: &'a GatewayStore,
    pub upstream: &'a Upstream,
    pub router: &'a super::federation::Router,
}

fn schema(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

fn tool(name: &str, title: &str, description: &str, input: Value, read_only: bool) -> Value {
    json!({"name":name,"title":title,"description":description,"inputSchema":input,
        "annotations":{"readOnlyHint":read_only,"destructiveHint":name=="t3_cancel_run",
            "idempotentHint":true,"openWorldHint":false}})
}

/// Tool list for a grant. Write tools are only listed for `operate` grants.
pub fn definitions(access: Access) -> Vec<Value> {
    let session = json!({"type":"string","description":"T3 thread ID (session_id) exactly as returned by t3_list_sessions."});
    let run = json!({"type":"string","description":"run_id returned by t3_send_message or t3_get_session."});
    let cursor = json!({"type":["integer","null"],"minimum":0});
    let limit = json!({"type":["integer","null"],"minimum":1,"maximum":100});
    let mut tools = vec![
        tool(
            "t3_list_projects",
            "List T3 projects",
            "List the T3 Code projects this connection is authorized for.",
            schema(json!({"cursor":cursor,"limit":limit}), &[]),
            true,
        ),
        tool(
            "t3_list_sessions",
            "List T3 sessions",
            "List existing T3 Code conversations (threads) in an authorized project, newest activity first, with title, agent, model, status and last activity. Omit project_id when only one project is authorized.",
            schema(
                json!({"project_id":{"type":["string","null"]},
                "status":{"type":["array","null"],"items":{"type":"string","enum":["idle","queued","running","waiting_for_approval","completed","failed","cancelled"]}},
                "title_contains":{"type":["string","null"],"maxLength":256},"cursor":cursor,"limit":limit}),
                &[],
            ),
            true,
        ),
        tool(
            "t3_get_session",
            "Get T3 session",
            "Get one T3 session: project, title, agent, model, runtime mode, status, active run and recent runs.",
            schema(json!({"session_id":session}), &["session_id"]),
            true,
        ),
        tool(
            "t3_get_session_status",
            "Get T3 session status",
            "Current normalized status of a T3 session, its active run and pending user questions or approvals.",
            schema(json!({"session_id":session}), &["session_id"]),
            true,
        ),
        tool(
            "t3_get_messages",
            "Read T3 history",
            "Read the canonical T3 history of a session, oldest first. Continue with cursor=next_cursor. view=messages shows user/assistant messages and plans; view=activity also includes tool calls, commands and approvals. Recover a truncated item with item_id and text_offset=next_text_offset.",
            schema(
                json!({"session_id":session,"cursor":cursor,"limit":limit,
                "view":{"type":["string","null"],"enum":["messages","activity",null]},
                "item_id":{"type":["string","null"]},"text_offset":cursor,
                "max_chars":{"type":["integer","null"],"minimum":200,"maximum":50000}}),
                &["session_id"],
            ),
            true,
        ),
        tool(
            "t3_get_run_status",
            "Get run status",
            "Normalized status of one run: queued, running, waiting_for_approval, completed, failed or cancelled.",
            schema(
                json!({"session_id":session,"run_id":run}),
                &["session_id", "run_id"],
            ),
            true,
        ),
        tool(
            "t3_wait_run",
            "Wait for run",
            "Wait up to timeout_seconds (max 50) for a run to finish or need attention, then return its status. A timeout never cancels the run; call again or poll later.",
            schema(
                json!({"session_id":session,"run_id":run,"timeout_seconds":{"type":["integer","null"],"minimum":1,"maximum":MAX_WAIT_SECONDS}}),
                &["session_id", "run_id"],
            ),
            true,
        ),
        tool(
            "t3_get_run_result",
            "Get run result",
            "Status plus the assistant messages and plans the agent produced for one run. final_text is the last assistant message once the run is terminal.",
            schema(
                json!({"session_id":session,"run_id":run,"max_chars":{"type":["integer","null"],"minimum":200,"maximum":50000}}),
                &["session_id", "run_id"],
            ),
            true,
        ),
        tool(
            "t3_get_events",
            "Get session events",
            "Incremental, resumable event feed for a session (messages, progress, tool calls, approvals, errors). Pass cursor=next_cursor from the previous call; an item still in progress is not consumed, so reconnecting never loses or duplicates finished events. Optionally filter by run_id.",
            schema(
                json!({"session_id":session,"cursor":cursor,"run_id":{"type":["string","null"]},"limit":limit,
                "max_chars":{"type":["integer","null"],"minimum":200,"maximum":50000}}),
                &["session_id"],
            ),
            true,
        ),
        tool(
            "t3_list_pending_requests",
            "List pending requests",
            "Questions the agent asked in a session and the number of approvals waiting. Approvals are answered by the owner in T3 Code, not through this connection.",
            schema(json!({"session_id":session}), &["session_id"]),
            true,
        ),
    ];
    if access == Access::Operate {
        tools.push(tool(
            "t3_send_message",
            "Send message to T3 session",
            "Continue an existing T3 session with a new user message, processed by that session's own agent (e.g. Codex). Never interrupts or steers an active run: if the agent is busy the message is queued behind it. client_request_id makes retries safe: the same ID returns the original run instead of sending twice.",
            schema(
                json!({"session_id":session,"message":{"type":"string","minLength":1,"maxLength":MAX_MESSAGE_CHARS},
                "client_request_id":{"type":"string","minLength":8,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}}),
                &["session_id","message","client_request_id"],
            ),
            false,
        ));
        tools.push(tool(
            "t3_cancel_run",
            "Cancel run",
            "Request interruption of a queued or running run in an authorized session.",
            schema(
                json!({"session_id":session,"run_id":run,"client_request_id":{"type":"string","minLength":8,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},
                "reason":{"type":["string","null"],"maxLength":500}}),
                &["session_id","run_id","client_request_id"],
            ),
            false,
        ));
    }
    tools
}

/// T3 run/thread status → contract status. The raw value is always returned as well.
pub fn normalize(status: &str, pending_requests: u64) -> &'static str {
    match status {
        "idle" => "idle",
        "preparing" | "queued" => "queued",
        "starting" | "running" if pending_requests > 0 => "waiting_for_approval",
        "starting" | "running" => "running",
        "waiting" => "waiting_for_approval",
        "completed" => "completed",
        "failed" => "failed",
        "interrupted" | "cancelled" | "rolled_back" => "cancelled",
        _ => "running",
    }
}

fn terminal(status: &str) -> bool {
    matches!(
        status,
        "completed" | "failed" | "interrupted" | "cancelled" | "rolled_back"
    )
}

fn string(args: &Map<String, Value>, name: &str) -> Result<Option<String>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(denied(
            "invalid_arguments",
            format!("{name} must be a string"),
        )),
    }
}

fn required(args: &Map<String, Value>, name: &str) -> Result<String> {
    string(args, name)?
        .filter(|v| !v.is_empty())
        .ok_or_else(|| denied("invalid_arguments", format!("{name} is required")))
}

fn integer(args: &Map<String, Value>, name: &str, min: u64, max: u64) -> Result<Option<u64>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|v| (min..=max).contains(v))
            .map(Some)
            .ok_or_else(|| denied("invalid_arguments", format!("{name} must be {min}..{max}"))),
    }
}

fn request_id(args: &Map<String, Value>) -> Result<String> {
    let id = required(args, "client_request_id")?;
    ensure!(
        (8..=128).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
        Denied(
            "invalid_arguments",
            "client_request_id must be 8..128 of [A-Za-z0-9._:-]".into()
        )
    );
    Ok(id)
}

fn session_view(detail: &Value) -> Value {
    let pending = detail["pendingRequestCount"].as_u64().unwrap_or(0);
    let raw = detail["status"].as_str().unwrap_or("idle");
    json!({
        "session_id": detail["threadId"], "project_id": detail["projectId"], "title": detail["title"],
        "agent": detail["providerInstanceId"], "model": detail["model"],
        "runtime_mode": detail["runtimeMode"], "interaction_mode": detail["interactionMode"],
        "status": normalize(raw, pending), "t3_status": raw,
        "active_run_id": detail["activeRunId"], "latest_run_id": detail["latestRunId"],
        "pending_request_count": pending, "branch": detail["branch"],
        "run_count": detail["runCount"], "item_count": detail["itemCount"],
        "archived": detail["archived"], "created_by": detail["createdBy"],
        "created_at": detail["createdAt"], "last_activity_at": detail["updatedAt"],
    })
}

fn run_view(run: &Value, pending: u64, active: bool) -> Value {
    let raw = run["status"].as_str().unwrap_or("running");
    json!({"run_id":run["runId"],"ordinal":run["ordinal"],
        "status":normalize(raw, if active { pending } else { 0 }),"t3_status":raw,
        "terminal":terminal(raw),"agent":run["providerInstanceId"],"model":run["model"],
        "requested_at":run["requestedAt"],"started_at":run["startedAt"],"completed_at":run["completedAt"]})
}

fn item_view(item: &Value) -> Value {
    json!({"position":item["position"],"item_id":item["itemId"],"run_id":item["runId"],
        "type":item["type"],"status":item["status"],"author":item["createdBy"],
        "source":item["creationSource"],"title":item["title"],"text":item["text"],
        "text_truncated":item["textTruncated"],"next_text_offset":item.get("nextTextOffset").cloned().unwrap_or(Value::Null),
        "updated_at":item["updatedAt"]})
}

fn event_kind(item: &Value) -> &'static str {
    let status = item["status"].as_str().unwrap_or_default();
    match item["type"].as_str().unwrap_or_default() {
        _ if status == "failed" => "error",
        "user_message" => "user_message",
        "assistant_message" => "assistant_message",
        "proposed_plan" | "plan" => "plan",
        "reasoning" => "progress",
        kind if kind.contains("approval") || kind.contains("request") || kind == "user_input" => {
            "approval_request"
        }
        _ if status == "waiting" => "approval_request",
        "command_execution" | "file_change" | "dynamic_tool" | "mcp_tool_call" | "web_search" => {
            "tool"
        }
        _ => "progress",
    }
}

impl ToolContext<'_> {
    async fn t3(&self, tool: &str, args: Value) -> Result<Value> {
        self.check_active().await?;
        let authorize = || -> Result<()> {
            ensure!(
                self.store.grant_unchanged(self.grant)?,
                Denied("forbidden", "selection changed before T3 request".into())
            );
            Ok(())
        };
        let result = self
            .upstream
            .call_checked(tool, args, READ_TIMEOUT, &authorize)
            .await?;
        self.check_active().await?;
        Ok(result)
    }

    async fn check_active(&self) -> Result<()> {
        if let Some(environment) = self.store.selected_environment()
            && self.store.remote_catalog_binding()?.is_some()
        {
            let credential = self.router.credential(self.store, environment).await?;
            ensure!(
                credential.expires > super::store::now(),
                Denied("forbidden", "credential expired".into())
            );
        }
        ensure!(
            self.store.grant_unchanged(self.grant)?,
            Denied("forbidden", "grant revoked or expired".into())
        );
        Ok(())
    }

    fn project_for(&self, requested: Option<String>) -> Result<String> {
        let projects = &self.grant.scope.projects;
        match requested {
            Some(project) if self.grant.allows_project(&project) => Ok(project),
            Some(_) => Err(denied(
                "forbidden",
                "this connection is not authorized for that project",
            )),
            None if projects.len() == 1 && !self.grant.scope.all_projects => {
                Ok(projects[0].clone())
            }
            None => Err(denied(
                "invalid_arguments",
                "project_id is required when several projects are authorized",
            )),
        }
    }

    /// Reads the T3 thread and checks project/session authorization before any use.
    async fn authorized(&self, session: &str, read: Value) -> Result<Value> {
        let mut args = json!({"threadId":session});
        args.as_object_mut()
            .unwrap()
            .extend(read.as_object().cloned().unwrap_or_default());
        let value = match self.t3("t3_thread_read", args).await {
            Ok(value) => value,
            Err(error) if error.downcast_ref::<ToolFailure>().is_some() => {
                return Err(denied("not_found", "session not found or not authorized"));
            }
            Err(error) => return Err(error),
        };
        let project = value["thread"]["projectId"].as_str().unwrap_or_default();
        if !self.grant.allows_session(project, session) {
            return Err(denied("not_found", "session not found or not authorized"));
        }
        Ok(value)
    }

    /// The project of a session this grant may see; `not_found` otherwise.
    pub async fn session_project(&self, session: &str) -> Result<String> {
        let read = self
            .authorized(session, json!({"limit":1,"runLimit":1,"maxCharsPerItem":1}))
            .await?;
        Ok(read["thread"]["projectId"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    fn require_operate(&self) -> Result<()> {
        if self.grant.scope.access != Access::Operate {
            return Err(denied("forbidden", "this connection is read-only"));
        }
        Ok(())
    }

    async fn run_snapshot(&self, session: &str, run_id: &str) -> Result<(Value, Value)> {
        let read = self
            .authorized(
                session,
                json!({"limit":1,"runLimit":50,"maxCharsPerItem":1}),
            )
            .await?;
        let detail = &read["thread"];
        let pending = detail["pendingRequestCount"].as_u64().unwrap_or(0);
        let active = detail["activeRunId"].as_str() == Some(run_id);
        let run = read["recentRuns"]
            .as_array()
            .and_then(|runs| runs.iter().find(|r| r["runId"].as_str() == Some(run_id)))
            .map(|run| run_view(run, pending, active));
        let run = match run {
            Some(run) => run,
            None if self
                .store
                .run_by_id(&self.grant.id, run_id)?
                .is_some_and(|record| record.session_id == session) =>
            {
                json!({"run_id":run_id,"status":"queued","t3_status":"unknown","terminal":false})
            }
            None => return Err(denied("not_found", "run not found in this session")),
        };
        Ok((detail.clone(), run))
    }

    pub async fn call(&self, name: &str, args: &Map<String, Value>) -> Result<Value> {
        self.check_active().await?;
        match name {
            "t3_list_projects" => {
                let cursor = integer(args, "cursor", 0, u64::MAX)?.unwrap_or(0) as usize;
                let limit = integer(args, "limit", 1, 100)?.unwrap_or(50) as usize;
                let mut all = Vec::new();
                let mut next = Some(0u64);
                while let Some(position) = next.take() {
                    let page = self
                        .t3("t3_project_list", json!({"cursor":position,"limit":100}))
                        .await?;
                    for project in page["projects"].as_array().into_iter().flatten() {
                        let id = project["id"].as_str().unwrap_or_default();
                        if self.grant.allows_project(id) && project["deletedAt"].is_null() {
                            all.push(json!({"project_id":id,"title":project["title"],
                                "repository":project["repositoryIdentity"]["displayName"],
                                "updated_at":project["updatedAt"]}));
                        }
                    }
                    next = page["nextCursor"].as_u64().filter(|_| all.len() < 10_000);
                }
                let page: Vec<_> = all.iter().skip(cursor).take(limit).cloned().collect();
                let next_cursor = (cursor + page.len() < all.len()).then_some(cursor + page.len());
                Ok(json!({"projects":page,"next_cursor":next_cursor,"total":all.len()}))
            }
            "t3_list_sessions" => {
                let project = self.project_for(string(args, "project_id")?)?;
                let mut upstream = json!({"projectId":project,
                    "cursor":integer(args,"cursor",0,u64::MAX)?.unwrap_or(0),
                    "limit":integer(args,"limit",1,100)?.unwrap_or(25)});
                if let Some(title) =
                    string(args, "title_contains")?.filter(|t| !t.trim().is_empty())
                {
                    upstream["titleContains"] =
                        title.trim().chars().take(256).collect::<String>().into();
                }
                let wanted: Option<Vec<String>> = match args.get("status") {
                    None | Some(Value::Null) => None,
                    Some(Value::Array(values)) => Some(
                        values
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect(),
                    ),
                    Some(_) => return Err(denied("invalid_arguments", "status must be an array")),
                };
                let list = self.t3("t3_thread_list", upstream).await?;
                let sessions: Vec<Value> = list["threads"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|t| {
                        self.grant
                            .allows_session(&project, t["threadId"].as_str().unwrap_or_default())
                    })
                    .map(|t| {
                        let raw = t["status"].as_str().unwrap_or("idle");
                        json!({"session_id":t["threadId"],"project_id":project,"title":t["title"],
                            "agent":t["providerInstanceId"],"model":t["model"],"runtime_mode":t["runtimeMode"],
                            "status":normalize(raw, 0),"t3_status":raw,"latest_run_id":t["latestRunId"],
                            "parent_session_id":t["parentThreadId"],"item_count":t["itemCount"],
                            "created_at":t["createdAt"],"last_activity_at":t["updatedAt"]})
                    })
                    .filter(|s| {
                        wanted.as_ref().is_none_or(|w| {
                            w.iter().any(|status| s["status"].as_str() == Some(status))
                        })
                    })
                    .collect();
                Ok(json!({"project_id":project,"sessions":sessions,
                    "next_cursor":list["nextCursor"],"total_in_project":list["total"]}))
            }
            "t3_get_session" => {
                let session = required(args, "session_id")?;
                let read = self
                    .authorized(
                        &session,
                        json!({"limit":1,"runLimit":10,"maxCharsPerItem":1}),
                    )
                    .await?;
                let detail = &read["thread"];
                let pending = detail["pendingRequestCount"].as_u64().unwrap_or(0);
                let runs: Vec<_> = read["recentRuns"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|r| run_view(r, pending, detail["activeRunId"] == r["runId"]))
                    .collect();
                let mut view = session_view(detail);
                view["recent_runs"] = runs.into();
                Ok(view)
            }
            "t3_get_session_status" => {
                let session = required(args, "session_id")?;
                let read = self
                    .authorized(
                        &session,
                        json!({"limit":1,"runLimit":1,"maxCharsPerItem":1}),
                    )
                    .await?;
                let view = session_view(&read["thread"]);
                Ok(
                    json!({"session_id":session,"project_id":view["project_id"],"status":view["status"],"t3_status":view["t3_status"],
                    "active_run_id":view["active_run_id"],"latest_run_id":view["latest_run_id"],
                    "pending_request_count":view["pending_request_count"],
                    "last_activity_at":view["last_activity_at"]}),
                )
            }
            "t3_get_messages" => {
                let session = required(args, "session_id")?;
                let view = string(args, "view")?.unwrap_or_else(|| "messages".into());
                ensure!(
                    view == "messages" || view == "activity",
                    Denied(
                        "invalid_arguments",
                        "view must be messages or activity".into()
                    )
                );
                let mut read = json!({"view":view,"limit":integer(args,"limit",1,100)?.unwrap_or(30),
                    "runLimit":1,"maxCharsPerItem":integer(args,"max_chars",200,50_000)?.unwrap_or(8000)});
                if let Some(cursor) = integer(args, "cursor", 0, u64::MAX)? {
                    read["afterPosition"] = cursor.into();
                }
                if let Some(item) = string(args, "item_id")? {
                    read["itemId"] = item.into();
                    read["textOffset"] = integer(args, "text_offset", 0, u64::MAX)?
                        .unwrap_or(0)
                        .into();
                }
                let page = self.authorized(&session, read).await?;
                let items: Vec<_> = page["items"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(item_view)
                    .collect();
                Ok(json!({"session_id":session,"items":items,
                    "next_cursor":page["nextPosition"],"has_more":page["hasMore"]}))
            }
            "t3_get_run_status" => {
                let session = required(args, "session_id")?;
                let run = required(args, "run_id")?;
                let (detail, run) = self.run_snapshot(&session, &run).await?;
                Ok(json!({"session_id":session,"run":run,
                    "pending_request_count":detail["pendingRequestCount"]}))
            }
            "t3_wait_run" => {
                let session = required(args, "session_id")?;
                let run_id = required(args, "run_id")?;
                let seconds = integer(args, "timeout_seconds", 1, MAX_WAIT_SECONDS)?.unwrap_or(25);
                self.run_snapshot(&session, &run_id).await?;
                let waited = self
                    .upstream
                    .call(
                        "t3_thread_wait",
                        json!({"threadId":session,"runId":run_id,"timeoutMs":seconds*1000}),
                        Duration::from_secs(seconds + 30),
                    )
                    .await?;
                let (detail, run) = self.run_snapshot(&session, &run_id).await?;
                Ok(
                    json!({"session_id":session,"timed_out":waited["timedOut"],"run":run,
                    "pending_request_count":detail["pendingRequestCount"]}),
                )
            }
            "t3_get_run_result" => {
                let session = required(args, "session_id")?;
                let run_id = required(args, "run_id")?;
                let max = integer(args, "max_chars", 200, 50_000)?.unwrap_or(20_000);
                let (_, run) = self.run_snapshot(&session, &run_id).await?;
                let start = self
                    .store
                    .run_by_id(&self.grant.id, &run_id)?
                    .and_then(|r| r.start_position);
                let mut messages = Vec::new();
                // Start near the recorded position; rescan from the beginning if the
                // run's items were not found there (e.g. a run started from T3's UI).
                for origin in [start, None] {
                    let mut cursor = origin;
                    let mut seen_run = false;
                    for _ in 0..RESULT_SCAN_PAGES {
                        let mut read = json!({"view":"messages","limit":100,"runLimit":1,"maxCharsPerItem":max});
                        if let Some(position) = cursor {
                            read["afterPosition"] = position.into();
                        }
                        let page = self.authorized(&session, read).await?;
                        for item in page["items"].as_array().into_iter().flatten() {
                            if item["runId"].as_str() == Some(run_id.as_str()) {
                                seen_run = true;
                                if item["type"].as_str() != Some("user_message") {
                                    messages.push(item_view(item));
                                }
                            }
                        }
                        match page["nextPosition"].as_u64() {
                            Some(next) if page["hasMore"] == true => cursor = Some(next),
                            _ => break,
                        }
                    }
                    if seen_run || origin.is_none() {
                        break;
                    }
                }
                let final_text = run["terminal"]
                    .as_bool()
                    .filter(|t| *t)
                    .and_then(|_| {
                        messages
                            .iter()
                            .rev()
                            .find(|m| m["type"] == "assistant_message")
                            .map(|m| m["text"].clone())
                    })
                    .unwrap_or(Value::Null);
                Ok(
                    json!({"session_id":session,"run":run,"complete":run["terminal"],
                    "final_text":final_text,"messages":messages}),
                )
            }
            "t3_get_events" => {
                let session = required(args, "session_id")?;
                let filter = string(args, "run_id")?;
                let mut read = json!({"view":"activity","limit":integer(args,"limit",1,100)?.unwrap_or(50),
                    "runLimit":5,"maxCharsPerItem":integer(args,"max_chars",200,50_000)?.unwrap_or(4000)});
                let cursor = integer(args, "cursor", 0, u64::MAX)?;
                if let Some(cursor) = cursor {
                    read["afterPosition"] = cursor.into();
                }
                let page = self.authorized(&session, read).await?;
                let detail = &page["thread"];
                let pending = detail["pendingRequestCount"].as_u64().unwrap_or(0);
                let mut events = Vec::new();
                let mut next_cursor = cursor.map(Value::from).unwrap_or(Value::Null);
                let mut in_progress = Value::Null;
                for item in page["items"].as_array().into_iter().flatten() {
                    let status = item["status"].as_str().unwrap_or_default();
                    let live = item["runId"].is_string() && item["runId"] == detail["activeRunId"];
                    if live && matches!(status, "pending" | "running" | "waiting" | "idle") {
                        // Not consumed: the next call re-reads it once it settles.
                        let mut view = item_view(item);
                        view["kind"] = event_kind(item).into();
                        in_progress = view;
                        break;
                    }
                    next_cursor = item["position"].clone();
                    if filter
                        .as_deref()
                        .is_some_and(|run| item["runId"].as_str() != Some(run))
                    {
                        continue;
                    }
                    let mut view = item_view(item);
                    view["kind"] = event_kind(item).into();
                    events.push(view);
                }
                let runs: Vec<_> = page["recentRuns"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|r| {
                        filter
                            .as_deref()
                            .is_none_or(|run| r["runId"].as_str() == Some(run))
                    })
                    .map(|r| run_view(r, pending, detail["activeRunId"] == r["runId"]))
                    .collect();
                Ok(
                    json!({"session_id":session,"events":events,"next_cursor":next_cursor,
                    "in_progress":in_progress,"has_more":page["hasMore"] == true || !in_progress.is_null(),
                    "session_status":normalize(detail["status"].as_str().unwrap_or("idle"), pending),
                    "runs":runs}),
                )
            }
            "t3_list_pending_requests" => {
                let session = required(args, "session_id")?;
                let read = self
                    .authorized(
                        &session,
                        json!({"limit":1,"runLimit":1,"maxCharsPerItem":1}),
                    )
                    .await?;
                let listed = self
                    .t3("t3_pending_request_list", json!({"threadId":session}))
                    .await?;
                let mut questions = Vec::new();
                for id in listed["requestIds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(20)
                {
                    if let Ok(request) = self
                        .t3(
                            "t3_pending_request_read",
                            json!({"threadId":session,"requestId":id}),
                        )
                        .await
                    {
                        questions.push(request);
                    }
                }
                let total = read["thread"]["pendingRequestCount"].as_u64().unwrap_or(0);
                Ok(json!({"session_id":session,"pending_request_count":total,
                    "user_questions":questions,
                    "approvals_waiting":total.saturating_sub(questions.len() as u64),
                    "how_to_answer":"Open this session in T3 Code to approve or answer; this connection cannot grant approvals."}))
            }
            "t3_send_message" => {
                self.require_operate()?;
                let session = required(args, "session_id")?;
                let message = required(args, "message")?;
                ensure!(
                    message.chars().count() <= MAX_MESSAGE_CHARS,
                    Denied("invalid_arguments", "message too long".into())
                );
                let client_request = request_id(args)?;
                let digest = sha256_b64(message.as_bytes());
                if let Some(existing) = self.store.run(&self.grant.id, &client_request)? {
                    ensure!(
                        existing.session_id == session && existing.message_sha256 == digest,
                        Denied(
                            "conflict",
                            "client_request_id was already used for a different message".into()
                        )
                    );
                    let (_, run) = self.run_snapshot(&session, &existing.run_id).await?;
                    return Ok(json!({"session_id":session,"run_id":existing.run_id,
                        "message_id":existing.message_id,"delivery":existing.delivery,
                        "status":run["status"],"duplicate":true}));
                }
                // Highest position before sending, so the result scan can start there.
                let latest = self
                    .authorized(
                        &session,
                        json!({"view":"messages","limit":1,"runLimit":1,"maxCharsPerItem":1}),
                    )
                    .await?;
                let start_position = latest["thread"]["itemCount"]
                    .as_u64()
                    .and_then(|count| count.checked_sub(1));
                let sent = self
                    .t3(
                        "t3_thread_send",
                        json!({"threadId":session,"message":message,"mode":"queue",
                            "clientRequestId":format!("omabridge:{}:{client_request}", self.store.ledger_principal(&self.grant.id))}),
                    )
                    .await
                    .map_err(|error| match error.downcast_ref::<ToolFailure>() {
                        Some(failure) => denied("rejected_by_t3", failure.to_string()),
                        None => error,
                    })?;
                let run_id = sent["runId"]
                    .as_str()
                    .context("T3 returned no run")?
                    .to_owned();
                let record = self.store.record_run(
                    &client_request,
                    RunRecord {
                        grant: self.grant.id.clone(),
                        session_id: session.clone(),
                        run_id: run_id.clone(),
                        message_id: sent["messageId"].as_str().unwrap_or_default().to_owned(),
                        message_sha256: digest,
                        start_position: start_position.map(|p| p.saturating_sub(5)),
                        delivery: sent["delivery"].as_str().unwrap_or("queued").to_owned(),
                        created: super::store::now(),
                    },
                )?;
                let raw = sent["status"].as_str().unwrap_or("queued");
                Ok(
                    json!({"session_id":session,"run_id":record.run_id,"message_id":record.message_id,
                    "delivery":record.delivery,"status":normalize(raw,0),"t3_status":raw,"duplicate":false}),
                )
            }
            "t3_cancel_run" => {
                self.require_operate()?;
                let session = required(args, "session_id")?;
                let run_id = required(args, "run_id")?;
                let client_request = request_id(args)?;
                self.run_snapshot(&session, &run_id).await?;
                let mut upstream = json!({"threadId":session,"runId":run_id,
                    "clientRequestId":format!("omabridge:{}:cancel:{client_request}", self.store.ledger_principal(&self.grant.id))});
                if let Some(reason) = string(args, "reason")? {
                    upstream["reason"] = reason.chars().take(500).collect::<String>().into();
                }
                let result = self.t3("t3_thread_interrupt", upstream).await?;
                let (_, run) = self.run_snapshot(&session, &run_id).await?;
                Ok(
                    json!({"session_id":session,"run_id":run_id,"result":result["status"],"run":run}),
                )
            }
            _ => bail!(Denied("unknown_tool", format!("unknown tool {name}"))),
        }
    }
}
