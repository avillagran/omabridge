mod headless;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use iroh::RelayUrl;
use omabridge::{
    Client, Invitation, NetOptions, Node, PairDecision, Relay, Store, connect_through_server,
    find_peer, forward_target, forward_through_server, read_document, t3_pair_through_server,
    unix_time, write_document,
};
use serde_json::json;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(
    version,
    about = "Private, encrypted device-to-service bridges. Experimental; not a VPN."
)]
struct Args {
    #[arg(long, global = true, default_value_os_t = omabridge::default_state_dir())]
    state_dir: PathBuf,
    #[arg(long, global = true, default_value = "device")]
    name: String,
    #[arg(long, global = true, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
    /// Relay for peers behind NAT or private IPs: `public` (n0's relays), `none`
    /// (direct only) or an HTTPS URL. Default: the device's saved choice, else public.
    #[arg(long, global = true)]
    relay: Option<Relay>,
    /// Same as `--relay <URL>`; kept for existing units.
    #[arg(long, global = true, hide = true, conflicts_with = "relay")]
    relay_url: Option<RelayUrl>,
    /// Opt in to bounded T3 tunnel compression; enable on both peers. See docs/host-domains.md.
    #[arg(long, global = true)]
    compress_t3: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init,
    /// Poll a local sanitized desktop view and publish verified client catalogs.
    CatalogPublish {
        #[arg(long, required_unless_present = "auto", requires = "policy")]
        desktop_client: Option<PathBuf>,
        #[arg(long, required_unless_present = "auto", requires = "desktop_client")]
        policy: Option<PathBuf>,
        /// Needs no desktop view or policy: publish every host that consented to
        /// this bridge, and this device, to every device approved for all hosts.
        #[arg(long, conflicts_with_all = ["desktop_client", "policy"])]
        auto: bool,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
        interval: u64,
        #[arg(long)]
        once: bool,
    },
    /// Host a private iroh relay. Plain HTTP is loopback-only; public binding requires TLS.
    Relay {
        #[arg(long, default_value = "127.0.0.1:3340")]
        listen: SocketAddr,
        /// Authenticated endpoint IDs admitted by the relay. Repeat for every peer.
        #[arg(long = "allow-peer", required = true)]
        peers: Vec<iroh::EndpointId>,
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },
    /// Start an owned T3 headless with a new/managed private home, then publish it.
    T3 {
        #[arg(long)]
        t3_binary: PathBuf,
        #[arg(long)]
        t3_home: PathBuf,
        #[arg(long)]
        t3_port: u16,
    },
    Serve {
        /// Explicit consent to issue bounded read-only sessions from owned local T3 instances.
        #[arg(long)]
        enrollment_config: Option<PathBuf>,
        /// Explicit loopback target, e.g. t3=127.0.0.1:3773. Repeat for several services.
        #[arg(long = "service", required = true)]
        services: Vec<String>,
        /// Follow T3's loopback port in this runtime file for new connections.
        #[arg(long)]
        t3_runtime: Option<PathBuf>,
    },
    /// Publish a fixed-origin HTTPS API gateway in this process. No Python or helper daemon.
    Egress {
        #[arg(long)]
        origin: String,
        #[arg(long, default_value = "egress")]
        service: String,
        /// Name of the exit host's environment variable; never pass a literal key.
        #[arg(long)]
        key_env: Option<String>,
    },
    Invite {
        #[arg(long = "service", required = true)]
        services: Vec<String>,
        #[arg(long, default_value_t = 300)]
        ttl: u64,
        /// Private invitation file; refuses to overwrite an existing path.
        #[arg(long)]
        output: PathBuf,
        /// Print an invitation URI as a terminal QR. Treat the QR as secret.
        #[arg(long)]
        qr: bool,
        /// Approving also gives every host that consented to this bridge, with
        /// T3's default scopes (write access). Needs `--service t3`.
        #[arg(long)]
        all_hosts: bool,
    },
    Pair {
        #[arg(long)]
        invite_file: PathBuf,
    },
    Pending,
    Approve {
        peer: String,
        /// Required when this peer claimed more than one live invitation.
        #[arg(long)]
        invitation_id: Option<String>,
    },
    Peers,
    Revoke {
        peer: String,
    },
    /// Rename this device. A running `serve` tells paired devices within seconds.
    Rename {
        name: String,
    },
    /// Remote MCP gateway so ChatGPT can work on existing T3 Code sessions.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Run one management request read as JSON on stdin and print the new snapshot.
    /// Shared by every front end (T3 Code, the Omarchy Control Panel, bar widgets).
    Manage,
    Forward {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        service: String,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        /// Explicit, private endpoint document for an already trusted peer after an address change.
        #[arg(long)]
        endpoint_file: Option<PathBuf>,
    },
    /// Connect stdin and stdout to a service a paired device granted, e.g. as
    /// `ssh -o ProxyCommand='omabridge connect --peer NAME --service ssh' NAME`.
    Connect {
        /// Endpoint ID or the device's name, when no other paired device has it.
        #[arg(long)]
        peer: String,
        #[arg(long)]
        service: String,
    },
    /// Allow a paired bridge to invite devices with full access to this device's
    /// T3, or withdraw that with `--withdraw`. Only this device can change it.
    BridgeConsent {
        /// Endpoint ID or the device's name, when no other paired device has it.
        #[arg(long)]
        peer: String,
        #[arg(long)]
        withdraw: bool,
    },
    /// Ask a paired device that shares `t3` for a one-use T3 pairing and print it
    /// as JSON (`environmentId`, `credential`, `label`). Treat the output as secret.
    T3Pair {
        /// Endpoint ID or the device's name, when no other paired device has it.
        #[arg(long)]
        peer: String,
    },
}

#[derive(Subcommand)]
enum McpCommand {
    /// Create an empty administrator-managed catalog. No OAuth grant is issued.
    PolicyCreate {
        #[arg(long)]
        policy: String,
        #[arg(long, default_value = "read")]
        access: omabridge::mcp::store::Access,
    },
    /// Inspect only policy IDs and selections, never credentials.
    PolicyShow {
        #[arg(long)]
        policy: String,
    },
    /// Replace one exact project's session selection in a managed catalog.
    PolicyAllow {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        project: String,
        #[arg(
            long = "session",
            required_unless_present = "all_sessions",
            conflicts_with = "all_sessions"
        )]
        sessions: Vec<String>,
        #[arg(long)]
        all_sessions: bool,
    },
    /// Withdraw one project, or the entire environment if project is omitted.
    PolicyRemove {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        environment: String,
        #[arg(long)]
        project: Option<String>,
    },
    /// Follow the official T3 runtime using existing consent and a fixed environment identity.
    FollowT3Runtime {
        /// Bind the separately consented environment slot rather than the legacy local upstream.
        #[arg(long)]
        environment_slot: bool,
        #[arg(long)]
        runtime: PathBuf,
        #[arg(long)]
        environment: String,
    },
    /// Follow an existing paired native catalog; each request refreshes its allowlist and routes.
    UseRemoteCatalog {
        #[arg(long)]
        device_state: std::path::PathBuf,
        #[arg(long)]
        bridge_id: String,
    },
    /// Intersect MCP access with an existing native catalog publisher's allowlist.
    UseCatalog {
        #[arg(long)]
        device_state: std::path::PathBuf,
        #[arg(long)]
        client_id: String,
    },
    /// Link the gateway to T3's own MCP via T3 OAuth. Reads the T3 pairing code from stdin.
    LinkT3 {
        /// Bind a separate MCP credential to this stable environment UUID.
        #[arg(long)]
        environment: Option<String>,
        #[arg(long, default_value = "http://127.0.0.1:3773")]
        t3_url: String,
        /// T3 runtime-mode ceiling: read-only, approval-required, auto-accept-edits, auto, full-access.
        #[arg(long, default_value = "approval-required")]
        access: String,
    },
    /// Create a one-time link code that authorizes one OAuth client for these projects.
    Grant {
        /// Explicit consent to a mutable administrator-managed catalog and access ceiling.
        #[arg(long, conflicts_with_all = ["environments", "projects", "sessions", "all_projects"])]
        managed_catalog: Option<String>,
        /// Explicit environment UUIDs (repeatable). Omitted means legacy local-only.
        #[arg(long = "environment")]
        environments: Vec<String>,
        #[arg(
            long = "project",
            required_unless_present_any = ["all_projects", "managed_catalog"],
            conflicts_with = "all_projects"
        )]
        projects: Vec<String>,
        /// Every T3 project, including projects created later.
        #[arg(long)]
        all_projects: bool,
        /// Restrict to these T3 session (thread) IDs. Repeatable.
        #[arg(long = "session")]
        sessions: Vec<String>,
        #[arg(long, default_value = "read")]
        access: omabridge::mcp::store::Access,
        #[arg(long, default_value = "chatgpt")]
        label: String,
        #[arg(long, default_value_t = 30)]
        ttl_days: u64,
        #[arg(long, default_value_t = 600)]
        code_ttl: u64,
    },
    Grants,
    Revoke {
        grant: String,
    },
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Status,
    /// Serve MCP + OAuth. Plain HTTP only on loopback (behind a TLS tunnel/proxy).
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        /// Public https origin ChatGPT reaches, e.g. https://t3-mcp.example.com
        #[arg(long)]
        public_url: Option<String>,
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// Additional https OAuth redirect host (chatgpt.com is allowed by default).
        #[arg(long = "allow-redirect-host")]
        redirect_hosts: Vec<String>,
        /// Do not offer MCP Events (webhook subscriptions).
        #[arg(long)]
        no_events: bool,
        /// Seconds between T3 polls while event subscriptions exist.
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=300))]
        events_poll_seconds: u64,
        /// Name reported as `host` in events. Defaults to this device's hostname.
        #[arg(long)]
        events_host: Option<String>,
        /// Testing only: also deliver events to plain-http loopback callbacks.
        #[arg(long, hide = true)]
        insecure_loopback_callbacks: bool,
    },
}

fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "t3".to_owned())
}

async fn mcp(state_dir: &std::path::Path, command: McpCommand) -> Result<()> {
    use omabridge::mcp::{server, store, upstream};
    let gateway = store::GatewayStore::open(state_dir)?;
    match command {
        McpCommand::PolicyCreate { policy, access } => {
            gateway.create_managed_policy(&policy, access)?;
            gateway
                .audit(json!({"event":"managed_policy_created","policy":policy,"access":access}))?;
            println!("{}", json!({"policy_created":policy,"access":access}));
        }
        McpCommand::PolicyShow { policy } => {
            println!(
                "{}",
                json!({"policy":policy,"selection":gateway.managed_policy(&policy)?.context("unknown policy")?})
            );
        }
        McpCommand::PolicyAllow {
            policy,
            environment,
            project,
            sessions,
            all_sessions,
        } => {
            gateway.select_managed_project(
                &policy,
                &environment,
                Some(&project),
                if all_sessions { None } else { Some(sessions) },
                false,
            )?;
            gateway.audit(json!({"event":"managed_policy_selection_changed","policy":policy,"environment":environment,"project":project,"removed":false}))?;
            println!("{}", json!({"policy_updated":policy}));
        }
        McpCommand::PolicyRemove {
            policy,
            environment,
            project,
        } => {
            gateway.select_managed_project(
                &policy,
                &environment,
                project.as_deref(),
                None,
                true,
            )?;
            gateway.audit(json!({"event":"managed_policy_selection_changed","policy":policy,"environment":environment,"project":project,"removed":true}))?;
            println!("{}", json!({"policy_updated":policy}));
        }
        McpCommand::FollowT3Runtime {
            runtime,
            environment,
            environment_slot,
        } => {
            let binding = store::RuntimeBinding {
                runtime,
                environment_id: environment,
            };
            let target = if environment_slot {
                gateway.environment_store(&binding.environment_id)?
            } else {
                gateway.clone()
            };
            let mut credential = target
                .upstream()?
                .context("existing MCP consent required; use the official link-t3 flow first")?;
            credential.url = binding.origin()?;
            let upstream =
                upstream::Upstream::for_environment(&credential, &binding.environment_id)?;
            upstream.verify_environment().await?;
            upstream
                .call(
                    "t3_project_list",
                    json!({"limit":1}),
                    Duration::from_secs(20),
                )
                .await
                .context("existing MCP consent not accepted; no credentials or grants changed")?;
            target.set_runtime_binding(&binding)?;
            gateway.audit(
                json!({"event":"t3_runtime_bound","environment_id":binding.environment_id}),
            )?;
            println!(
                "{}",
                json!({"runtime_bound":true,"environment_id":binding.environment_id,"origin":credential.url,"credential_renewed":false})
            );
        }
        McpCommand::UseRemoteCatalog {
            device_state,
            bridge_id,
        } => {
            gateway.set_remote_catalog_binding(&store::RemoteCatalogBinding {
                device_state,
                bridge_id,
            })?;
            println!("{}", json!({"catalog_policy":"remote_attached"}));
        }
        McpCommand::UseCatalog {
            device_state,
            client_id,
        } => {
            gateway.set_catalog_binding(&store::CatalogBinding {
                device_state,
                client_id,
            })?;
            println!("{}", json!({"catalog_policy":"attached"}));
        }
        McpCommand::LinkT3 {
            t3_url,
            access,
            environment,
        } => {
            if let Some(id) = &environment {
                upstream::Upstream::for_environment(
                    &store::UpstreamCredential {
                        url: t3_url.clone(),
                        token: String::new(),
                        access: access.clone(),
                        expires: u64::MAX,
                    },
                    id,
                )?
                .verify_environment()
                .await?;
            }
            let mut code = String::new();
            std::io::stdin().read_line(&mut code)?;
            ensure!(
                !code.trim().is_empty(),
                "provide the T3 pairing code on stdin"
            );
            let credential = upstream::link(&t3_url, code.trim(), &access).await?;
            let linked = match environment.as_deref() {
                Some(id) => upstream::Upstream::for_environment(&credential, id)?,
                None => upstream::Upstream::new(&credential)?,
            };
            linked
                .call(
                    "t3_project_list",
                    json!({"limit":1}),
                    Duration::from_secs(20),
                )
                .await
                .context("linked, but T3 MCP did not answer")?;
            if let Some(id) = &environment {
                upstream::Upstream::for_environment(&credential, id)?
                    .verify_environment()
                    .await?;
                gateway.environment_store(id)?.set_upstream(&credential)?;
            } else {
                gateway.set_upstream(&credential)?;
            }
            gateway
                .audit(json!({"event":"t3_linked","environment_id":environment,"access":access}))?;
            println!(
                "{}",
                json!({"linked":credential.url,"access":credential.access,"expires":credential.expires})
            );
        }
        McpCommand::Grant {
            managed_catalog,
            environments,
            projects,
            all_projects,
            sessions,
            access,
            label,
            ttl_days,
            code_ttl,
        } => {
            let scope = store::GrantScope {
                managed_catalog,
                environments,
                label,
                projects,
                all_projects,
                sessions: (!sessions.is_empty()).then_some(sessions),
                access,
                ttl: ttl_days.saturating_mul(86400),
            };
            let (code, expires) = gateway.create_link_code(scope.clone(), code_ttl)?;
            gateway.audit(
                json!({"event":"link_code_created","managed_catalog":scope.managed_catalog,"projects":scope.projects,"all_projects":scope.all_projects,
                "sessions":scope.sessions,"access":scope.access}),
            )?;
            println!(
                "{}",
                json!({"link_code":code,"code_expires":expires,"scope":scope})
            );
        }
        McpCommand::Grants => println!("{}", json!({"grants":gateway.grants()?})),
        McpCommand::Revoke { grant } => {
            ensure!(gateway.revoke(&grant)?, "unknown grant");
            gateway.audit(json!({"event":"grant_revoked","grant":grant}))?;
            println!("{}", json!({"revoked":grant}));
        }
        McpCommand::Audit { limit } => {
            for record in gateway.audit_tail(limit.min(10_000))? {
                println!("{record}");
            }
        }
        McpCommand::Status => {
            let (upstream, environment) = gateway.upstream_routed()?;
            let now = store::now();
            let grants = gateway.grants()?;
            println!(
                "{}",
                json!({"linked":upstream.as_ref().map(|u| json!({"t3":u.url,"access":u.access,"expires":u.expires})),
                "runtime_environment":environment,"active_grants":grants.iter().filter(|g| g.active(now)).count(),"grants":grants.len()})
            );
        }
        McpCommand::Serve {
            listen,
            public_url,
            tls_cert,
            tls_key,
            redirect_hosts,
            no_events,
            events_poll_seconds,
            events_host,
            insecure_loopback_callbacks,
        } => {
            let events = (!no_events).then(|| server::EventsConfig {
                poll: std::time::Duration::from_secs(events_poll_seconds),
                policy: omabridge::mcp::webhook::CallbackPolicy {
                    allow_loopback: insecure_loopback_callbacks,
                },
                host: events_host.unwrap_or_else(host_name),
            });
            let running = server::start(
                gateway,
                server::ServerConfig {
                    listen,
                    public_url,
                    tls: tls_cert.zip(tls_key),
                    redirect_hosts,
                    events,
                },
            )
            .await?;
            println!(
                "{}",
                json!({"event":"mcp_listening","listen":running.address.to_string(),
                "mcp":format!("{}/mcp", running.issuer)})
            );
            tokio::select! {
                result = shutdown_signal() => result?,
                result = running.join() => { result?; anyhow::bail!("MCP server stopped unexpectedly") }
            }
        }
    }
    Ok(())
}

/// `{"error":"<code>"}` and exit 1 on failure; nothing else reaches stdout or stderr,
/// since requests and results may hold invitation paths.
async fn manage(args: Args) -> Result<()> {
    use std::io::Read;
    let mut raw = Vec::new();
    let limit = omabridge::manage::REQUEST_LIMIT;
    let result = match std::io::stdin()
        .take(limit as u64 + 1)
        .read_to_end(&mut raw)
    {
        Ok(size) if size <= limit => match serde_json::from_slice::<serde_json::Value>(&raw) {
            Ok(request) => {
                let relay = args.relay.or(args.relay_url.map(Relay::Custom));
                match omabridge::manage::Manager::from_env(args.state_dir, args.bind, relay) {
                    Ok(manager) => manager.execute(&request).await,
                    Err(code) => Err(code),
                }
            }
            Err(_) => Err("invalid_command"),
        },
        _ => Err("invalid_command"),
    };
    match result {
        Ok(snapshot) => println!("{snapshot}"),
        Err(code) => {
            println!("{}", json!({ "error": code }));
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = term.recv() => {} }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        eprintln!("omabridge: {error:#}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<()> {
    if let Command::Relay {
        listen,
        peers,
        tls_cert,
        tls_key,
    } = &args.command
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut server = omabridge::relay::RelayServer::start(
            *listen,
            peers.clone(),
            tls_cert.as_deref().zip(tls_key.as_deref()),
        )
        .await?;
        println!(
            "{}",
            json!({"event":"relay_listening", "http":server.http_addr().map(|a| a.to_string()), "https":server.https_addr().map(|a| a.to_string()), "allowed_peers":peers.len()})
        );
        let result: Result<()> = tokio::select! {
            _ = term.recv() => Ok(()),
            _ = interrupt.recv() => Ok(()),
            result = server.join() => result.and_then(|_| anyhow::bail!("relay stopped unexpectedly")),
        };
        server.shutdown().await?;
        return result;
    }
    if let Command::Manage = args.command {
        return manage(args).await;
    }
    if let Command::Mcp { command } = args.command {
        return mcp(&args.state_dir, command).await;
    }
    let store = Store::open(&args.state_dir, &args.name)?;
    let relay = match args.relay.or(args.relay_url.map(Relay::Custom)) {
        Some(relay) => relay,
        None => Relay::load(&args.state_dir)?,
    };
    let options = NetOptions {
        compress_t3: args.compress_t3,
        bind: args.bind,
        relay,
    };
    match args.command {
        Command::Relay { .. } | Command::Mcp { .. } | Command::Manage => {
            unreachable!("handled before device state initialization")
        }
        Command::CatalogPublish {
            desktop_client,
            policy,
            auto,
            interval,
            once,
        } => {
            ensure!(
                desktop_client
                    .as_ref()
                    .is_none_or(|path| path.is_absolute()),
                "desktop client must be an absolute local path"
            );
            let publisher = omabridge::catalog_publisher::Publisher::new()?;
            loop {
                let pass = match (&desktop_client, &policy) {
                    (Some(desktop), Some(policy)) if !auto => publisher
                        .poll_once(&store, desktop, policy)
                        .await
                        .map(|changed| json!({"catalogChanged":changed})),
                    _ => publisher
                        .publish_auto(&store)
                        .await
                        .and_then(|report| Ok(serde_json::to_value(report)?)),
                };
                match pass {
                    Ok(report) => println!("{report}"),
                    Err(_) if !once => eprintln!("catalog_publish_unavailable"),
                    Err(_) => anyhow::bail!("catalog_publish_unavailable"),
                }
                if once {
                    break;
                }
                tokio::select! { _ = tokio::time::sleep(Duration::from_secs(interval)) => {}, _ = tokio::signal::ctrl_c() => break }
            }
        }
        Command::Init => println!("{}", json!({"id":store.id()?,"name":store.name()?})),
        Command::T3 {
            t3_binary,
            t3_home,
            t3_port,
        } => {
            // Register both handlers before creating an owned child. Dropping the
            // readiness future alone is not cleanup: stop and reap explicitly.
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let reservation = store.reserve_runtime()?;
            let mut managed =
                headless::spawn(&t3_binary, &t3_home, t3_port, &store.id()?, &args.state_dir)?;
            let readiness: Result<()> = tokio::select! {
                result = managed.wait_ready(t3_port) => result,
                _ = term.recv() => Err(anyhow::anyhow!("T3 startup interrupted")),
                _ = interrupt.recv() => Err(anyhow::anyhow!("T3 startup interrupted")),
            };
            if let Err(error) = readiness {
                managed.stop().await?;
                return Err(error);
            }
            let targets = BTreeMap::from([(
                "t3".to_owned(),
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, t3_port)),
            )]);
            let node =
                // Pairings come from this owned T3, not from the user's own one.
                match Node::start_with_t3_issuer(
                    store.clone(),
                    targets,
                    options,
                    reservation,
                    None,
                    None,
                    Some(Some(omabridge::t3_pair::T3Issuer {
                        cli: t3_binary.clone(),
                        base_dir: t3_home.clone(),
                    })),
                )
                .await
                {
                    Ok(node) => node,
                    Err(error) => {
                        managed.stop().await?;
                        return Err(error);
                    }
                };
            if let Err(error) = store.publish_endpoint(&node.addr(), &["t3".to_owned()]) {
                node.shutdown().await;
                managed.stop().await?;
                return Err(error);
            }
            println!(
                "{}",
                json!({"event":"listening","id":store.id()?,"address":node.addr(),"services":["t3"],"t3_log":managed.log,"t3_pid":managed.child.id()})
            );
            let outcome: Result<()> = tokio::select! {
                _ = term.recv() => Ok(()),
                _ = interrupt.recv() => Ok(()),
                result = managed.child.wait() => { result?; Err(anyhow::anyhow!("owned T3 process exited")) },
            };
            node.shutdown().await;
            managed.stop().await?;
            outcome?;
        }

        Command::Egress {
            origin,
            service,
            key_env,
        } => {
            let origin = omabridge::egress::Origin::parse(&origin)?;
            ensure!(
                omabridge::valid_service(&service),
                "invalid egress service name"
            );
            let key = key_env
                .map(|name| {
                    ensure!(
                        !name.is_empty()
                            && name.bytes().enumerate().all(|(i, b)| b == b'_'
                                || b.is_ascii_alphabetic()
                                || (i > 0 && b.is_ascii_digit())),
                        "invalid credential environment variable name"
                    );
                    std::env::var(name).map_err(|_| {
                        anyhow::anyhow!("requested API credential is not set on this exit host")
                    })
                })
                .transpose()?;
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let reservation = store.reserve_runtime()?;
            let gateway = omabridge::egress::Gateway::start(origin.clone(), key).await?;
            let node = Node::start_reserved(
                store.clone(),
                BTreeMap::from([(service.clone(), gateway.addr())]),
                options,
                reservation,
            )
            .await?;
            store.publish_endpoint(&node.addr(), std::slice::from_ref(&service))?;
            println!(
                "{}",
                json!({"event":"listening", "id":store.id()?, "address":node.addr(), "services":[service], "gateway":gateway.addr().to_string(), "origin":origin.as_str()})
            );
            tokio::select! { _ = term.recv() => {}, _ = interrupt.recv() => {} }
            node.shutdown().await;
            gateway.shutdown().await;
        }
        Command::Serve {
            services,
            enrollment_config,
            t3_runtime,
        } => {
            let mut targets = BTreeMap::new();
            for item in services {
                let (name, target) = item
                    .split_once('=')
                    .context("use --service name=127.0.0.1:port")?;
                ensure!(
                    targets
                        .insert(name.to_owned(), target.parse::<SocketAddr>()?)
                        .is_none(),
                    "duplicate service name"
                );
            }
            let authority: Option<std::sync::Arc<dyn omabridge::enrollment::EnrollmentAuthority>> =
                if let Some(path) = enrollment_config {
                    Some(omabridge::delegated_enrollment::load_authority(
                        store.clone(),
                        &path,
                    )?)
                } else {
                    None
                };
            let node = Node::start_reserved_with_configuration(
                store.clone(),
                targets.clone(),
                options,
                store.reserve_runtime()?,
                authority,
                t3_runtime,
            )
            .await?;
            store.publish_endpoint(&node.addr(), &targets.keys().cloned().collect::<Vec<_>>())?;
            println!(
                "{}",
                json!({"event":"listening","id":store.id()?,"address":node.addr(),"services":targets.keys().collect::<Vec<_>>()})
            );
            shutdown_signal().await?;
            node.shutdown().await;
        }
        Command::Invite {
            services,
            ttl,
            output,
            qr,
            all_hosts,
        } => {
            let (address, published) = store.active_endpoint()?;
            ensure!(
                services.iter().all(|s| published.contains(s)),
                "grant only currently published services"
            );
            let now = unix_time()?;
            let lifetime = Duration::from_secs(ttl);
            let token = if all_hosts {
                store.create_all_hosts_invite(&services, lifetime, now)?
            } else {
                store.create_invite(&services, lifetime, now)?
            };
            let invite = Invitation {
                version: 1,
                address,
                token,
                name: store.name()?,
                expires: now.checked_add(ttl).context("expiry overflow")?,
                manage: false,
            };
            write_document(&output, &invite, false)?;
            println!(
                "{}",
                json!({"invite_file":output,"expires":invite.expires,"services":services,"all_hosts":all_hosts})
            );
            if qr {
                let uri = format!(
                    "omabridge://pair/{}",
                    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&invite)?)
                );
                let code = qrcode::QrCode::new(uri.as_bytes())?;
                println!(
                    "{}",
                    code.render::<qrcode::render::unicode::Dense1x2>().build()
                );
            }
        }
        Command::Pair { invite_file } => {
            let invite: Invitation = read_document(&invite_file)?;
            let client = Client::new(store.clone(), options).await?;
            let result = client.pair(&invite, &store.name()?, unix_time()?).await;
            client.close().await;
            let status = match result? {
                PairDecision::Pending => "pending",
                PairDecision::Approved { .. } => "approved",
            };
            println!(
                "{}",
                json!({"status":status,"id":store.id()?,"peer":invite.address.id.to_string()})
            );
        }
        Command::Pending => println!("{}", json!({"pending":store.pending()?})),
        Command::Peers => println!("{}", json!({"peers":store.peers()?})),
        Command::Approve {
            peer,
            invitation_id,
        } => {
            store.approve_selected(&peer, invitation_id.as_deref(), unix_time()?)?;
            println!("{}", json!({"approved":peer}));
        }
        Command::Rename { name } => {
            store.set_name(name.trim())?;
            println!("{}", json!({"name":store.name()?}));
        }
        Command::Revoke { peer } => {
            store.revoke(&peer)?;
            println!("{}", json!({"revoked":peer}));
        }
        Command::Forward {
            peer,
            service,
            listen,
            endpoint_file,
        } => {
            ensure!(
                listen.ip().is_loopback(),
                "forward listeners must bind loopback"
            );
            let peer = find_peer(&store, &peer).map_err(anyhow::Error::msg)?.id;
            let explicit = match endpoint_file {
                Some(file) => {
                    #[derive(serde::Deserialize)]
                    struct Info {
                        address: iroh::EndpointAddr,
                    }
                    Some(read_document::<Info>(&file)?.address)
                }
                None => None,
            };
            // A running server forwards with the device's own endpoint; a second
            // endpoint with the same identity would take its relay connection.
            if let Some(served) =
                forward_through_server(&store, &peer, &service, listen, explicit.as_ref()).await
            {
                use tokio::io::AsyncReadExt;
                let (mut socket, local) = served?;
                println!(
                    "{}",
                    json!({"event":"forwarding","listen":local.to_string(),"peer":peer,"service":service})
                );
                let mut sink = [0u8; 64];
                tokio::select! {
                    _ = async { while matches!(socket.read(&mut sink).await, Ok(read) if read > 0) {} } => {
                        anyhow::bail!("server stopped")
                    }
                    result = shutdown_signal() => result?,
                }
                return Ok(());
            }
            let (_, address) =
                forward_target(&store, &peer, &service, explicit).map_err(anyhow::Error::msg)?;
            let client = Arc::new(Client::new(store.clone(), options).await?);
            // Verify the grant and target now; never report a usable local listener on a failed setup.
            let probe = client.open(&address, &service).await?;
            drop(probe);
            let listener = TcpListener::bind(listen).await?;
            println!(
                "{}",
                json!({"event":"forwarding","listen":listener.local_addr()?.to_string(),"peer":peer,"service":service})
            );
            tokio::select! {
                result = client.clone().forward(address, service, listener) => result?,
                result = shutdown_signal() => result?,
            }
            client.close().await;
        }
        Command::Connect { peer, service } => {
            let peer = find_peer(&store, &peer).map_err(anyhow::Error::msg)?.id;
            let mut stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
            // Through a running server, like `forward`, so the device keeps one identity.
            if let Some(served) = connect_through_server(&store, &peer, &service).await {
                let mut socket = served?;
                let _ = tokio::io::copy_bidirectional(&mut stdio, &mut socket).await;
            } else {
                let (_, address) =
                    forward_target(&store, &peer, &service, None).map_err(anyhow::Error::msg)?;
                let client = Client::new(store.clone(), options).await?;
                let mut pipe = client
                    .open(&address, &service)
                    .await
                    .map_err(|_| anyhow::Error::msg("omabridge_peer_unreachable"))?;
                let _ = pipe.transfer(stdio).await;
                drop(pipe);
                client.close().await;
            }
            // Tokio's stdin thread may still wait on a read nobody needs.
            std::process::exit(0);
        }
        Command::BridgeConsent { peer, withdraw } => {
            let peer = find_peer(&store, &peer).map_err(anyhow::Error::msg)?;
            store.set_bridge_consent(&peer.id, !withdraw)?;
            // The running server announces the change within seconds.
            println!("{}", json!({"peer":peer.id,"bridgeConsent":!withdraw}));
        }
        Command::T3Pair { peer } => {
            let peer = find_peer(&store, &peer).map_err(anyhow::Error::msg)?.id;
            // Through a running server, like `connect`, so the device keeps one identity.
            let pairing = if let Some(served) = t3_pair_through_server(&store, &peer).await {
                served?
            } else {
                let (_, address) =
                    forward_target(&store, &peer, "t3", None).map_err(anyhow::Error::msg)?;
                let client = Client::new(store.clone(), options).await?;
                let pairing = client.t3_pair(&address).await;
                client.close().await;
                pairing?
            };
            println!("{}", serde_json::to_string(&pairing)?);
        }
    }
    Ok(())
}
