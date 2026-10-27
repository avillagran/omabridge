//! Optional standalone management UI. Every operation goes through the Rust library.
//! Network and systemd work runs on one background worker thread with its own tokio
//! runtime, so the window never blocks; action buttons are disabled while it is busy.
use anyhow::{Context, Result};
use clap::Parser;
use eframe::egui::{self, Color32, RichText, Stroke};
use omabridge::{
    DeviceSnapshot, Store, default_state_dir,
    desktop::{Desktop, PairOutcome, PairStatus, RemoteRoute},
    theme::{self, Palette},
    units::{self, UnitContext, UnitSpec, Units},
    unix_time,
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc::{Receiver, Sender, channel},
    time::{Duration, Instant, SystemTime},
};

#[derive(Parser)]
#[command(version, about = "OmaBridge native device manager")]
struct Args {
    #[arg(long, default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
    #[arg(long, default_value = "device")]
    name: String,
    /// Local QUIC address used for pairing and probes (same default as the CLI).
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
    /// Relay for pairing and probes: `public`, `none` or an HTTPS URL.
    /// Default: the device's saved choice, else public.
    #[arg(long)]
    relay: Option<omabridge::Relay>,
    /// systemd user unit directory. Default: $XDG_CONFIG_HOME/systemd/user.
    #[arg(long)]
    units_dir: Option<PathBuf>,
    /// `omabridge` CLI written into background units. Default: next to this executable.
    #[arg(long)]
    omabridge_bin: Option<PathBuf>,
    /// Section shown at startup.
    #[arg(long, value_enum, default_value = "device")]
    section: Section,
    /// Check the real public state without creating a window or exposing secrets.
    #[arg(long)]
    check: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Locale {
    Es,
    En,
}
impl Locale {
    fn from_tag(tag: &str) -> Self {
        if tag.to_ascii_lowercase().starts_with("en") {
            Self::En
        } else {
            Self::Es
        }
    }
    fn system() -> Self {
        let tag = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .into_iter()
            .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
            .unwrap_or_else(|| "es".to_owned());
        Self::from_tag(&tag)
    }
    fn text(self, es: &'static str, en: &'static str) -> &'static str {
        if self == Self::Es { es } else { en }
    }
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum Section {
    Device,
    Requests,
    Devices,
    Routes,
    Services,
}
impl Section {
    const ALL: [Section; 5] = [
        Self::Device,
        Self::Requests,
        Self::Devices,
        Self::Routes,
        Self::Services,
    ];
    fn label(self, lang: Locale) -> &'static str {
        match self {
            Self::Device => lang.text("Dispositivo", "Device"),
            Self::Requests => lang.text("Solicitudes", "Requests"),
            Self::Devices => lang.text("Dispositivos", "Devices"),
            Self::Routes => lang.text("Rutas", "Routes"),
            Self::Services => lang.text("Servicios", "Services"),
        }
    }
}

#[derive(Clone)]
enum Confirm {
    Approve {
        id: String,
        invitation: String,
        name: String,
        services: String,
    },
    Revoke {
        id: String,
        name: String,
    },
    Install {
        context: UnitContext,
        spec: UnitSpec,
        unit: String,
        exec: String,
    },
    Start(String),
    Stop(String),
    Remove(String),
}

enum Job {
    Pair { path: PathBuf, discard: bool },
    Probe { peer: String, service: String },
    ScanUnits,
    Install(UnitContext, UnitSpec),
    Start(String),
    Stop(String),
    Remove(String),
}

#[derive(Clone, Copy)]
enum UnitOp {
    Install,
    Start,
    Stop,
    Remove,
}

struct UnitRow {
    name: String,
    managed: bool,
    active: String,
    enabled: String,
}

enum Done {
    Pair(Result<PairOutcome, String>),
    Probe {
        key: (String, String),
        result: Result<Duration, String>,
    },
    Units(Result<Vec<UnitRow>, String>),
    UnitOp {
        op: UnitOp,
        name: String,
        result: Result<(), String>,
    },
}

/// Error text shown to the user: library messages only, bounded, single line.
fn shown(error: anyhow::Error) -> String {
    format!("{error:#}")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect()
}

fn scan_units(units: &Units) -> Result<Vec<UnitRow>> {
    units
        .list()?
        .into_iter()
        .map(|file| {
            let status = units.status(&file.name)?;
            Ok(UnitRow {
                name: file.name,
                managed: file.managed,
                active: status.active,
                enabled: status.enabled,
            })
        })
        .collect()
}

fn spawn_worker(
    desktop: Desktop,
    units: Units,
    ctx: egui::Context,
) -> Result<(Sender<Job>, Receiver<Done>)> {
    let (jobs, inbox) = channel::<Job>();
    let (outbox, results) = channel::<Done>();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    std::thread::Builder::new()
        .name("omabridge-gui-worker".into())
        .spawn(move || {
            for job in inbox {
                let done = match job {
                    Job::Pair { path, discard } => Done::Pair(
                        runtime
                            .block_on(desktop.pair(&path, discard))
                            .map_err(shown),
                    ),
                    Job::Probe { peer, service } => {
                        let result = runtime
                            .block_on(desktop.probe(&peer, &service))
                            .map_err(shown);
                        Done::Probe {
                            key: (peer, service),
                            result,
                        }
                    }
                    Job::ScanUnits => Done::Units(scan_units(&units).map_err(shown)),
                    Job::Install(context, spec) => {
                        let name = spec.unit_name().unwrap_or_default();
                        let result = units.install(&context, &spec).map(drop).map_err(shown);
                        Done::UnitOp {
                            op: UnitOp::Install,
                            name,
                            result,
                        }
                    }
                    Job::Start(name) => Done::UnitOp {
                        op: UnitOp::Start,
                        result: units.enable_now(&name).map_err(shown),
                        name,
                    },
                    Job::Stop(name) => Done::UnitOp {
                        op: UnitOp::Stop,
                        result: units.disable_now(&name).map_err(shown),
                        name,
                    },
                    Job::Remove(name) => Done::UnitOp {
                        op: UnitOp::Remove,
                        result: units.remove(&name).map_err(shown),
                        name,
                    },
                };
                if outbox.send(done).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        })?;
    Ok((jobs, results))
}

struct Notice {
    text: String,
    error: bool,
}

struct LoadedTheme {
    source: PathBuf,
    modified: Option<SystemTime>,
    palette: Palette,
}

fn modified(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn load_theme() -> Option<LoadedTheme> {
    theme::load_current().map(|(source, palette)| LoadedTheme {
        modified: modified(&source),
        source,
        palette,
    })
}

fn rgb(c: theme::Rgb) -> Color32 {
    Color32::from_rgb(c[0], c[1], c[2])
}

fn visuals_for(theme: Option<&LoadedTheme>) -> egui::Visuals {
    let Some(theme) = theme else {
        return egui::Visuals::dark();
    };
    let p = &theme.palette;
    let mut v = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    let (bg, fg, accent) = (rgb(p.background), rgb(p.foreground), rgb(p.accent));
    v.panel_fill = bg;
    v.window_fill = rgb(p.surface);
    v.window_stroke = Stroke::new(1.0_f32, rgb(p.muted));
    v.extreme_bg_color = rgb(p.extreme);
    v.code_bg_color = rgb(p.extreme);
    v.faint_bg_color = rgb(p.surface);
    v.hyperlink_color = accent;
    v.error_fg_color = rgb(p.error);
    v.warn_fg_color = accent;
    v.selection.bg_fill = accent.gamma_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0_f32, fg);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = bg;
    w.noninteractive.weak_bg_fill = bg;
    w.noninteractive.bg_stroke = Stroke::new(1.0_f32, rgb(p.muted));
    w.noninteractive.fg_stroke.color = fg;
    w.inactive.bg_fill = rgb(p.surface);
    w.inactive.weak_bg_fill = rgb(p.surface);
    w.inactive.fg_stroke.color = fg;
    for state in [&mut w.hovered, &mut w.open] {
        state.bg_fill = rgb(p.selection);
        state.weak_bg_fill = rgb(p.selection);
        state.bg_stroke = Stroke::new(1.0_f32, accent);
        state.fg_stroke.color = fg;
    }
    w.active.bg_fill = accent.gamma_multiply(0.5);
    w.active.weak_bg_fill = accent.gamma_multiply(0.5);
    w.active.bg_stroke = Stroke::new(1.0_f32, accent);
    w.active.fg_stroke.color = fg;
    v
}

struct Manager {
    desktop: Desktop,
    state: DeviceSnapshot,
    published: Option<Vec<String>>,
    routes: Vec<RemoteRoute>,
    selected_service: String,
    locale: Locale,
    section: Section,
    notice: Option<Notice>,
    last_invite: Option<PathBuf>,
    confirmation: Option<Confirm>,
    // background work
    jobs: Option<Sender<Job>>,
    results: Option<Receiver<Done>>,
    running: usize,
    units: Units,
    unit_context: Result<UnitContext, String>,
    unit_rows: Option<Result<Vec<UnitRow>, String>>,
    probes: BTreeMap<(String, String), Result<Duration, String>>,
    // forms
    pair_path: String,
    pair_discard: bool,
    pair_outcome: Option<PairOutcome>,
    publish_services: String,
    publish_bind: String,
    forward_route: Option<(String, String)>,
    forward_port: String,
    // theme
    theme: Option<LoadedTheme>,
    theme_checked: Instant,
    visuals: egui::Visuals,
}

impl Manager {
    fn new(
        desktop: Desktop,
        units: Units,
        unit_context: Result<UnitContext, String>,
    ) -> Result<Self> {
        let state = desktop.refresh()?;
        let published = desktop.published_services().ok();
        let selected_service = published
            .as_ref()
            .and_then(|items| items.first())
            .cloned()
            .unwrap_or_default();
        let routes = desktop.remote_routes().unwrap_or_default();
        let theme = load_theme();
        let visuals = visuals_for(theme.as_ref());
        Ok(Self {
            desktop,
            state,
            published,
            routes,
            selected_service,
            locale: Locale::system(),
            section: Section::Device,
            notice: None,
            last_invite: None,
            confirmation: None,
            jobs: None,
            results: None,
            running: 0,
            units,
            unit_context,
            unit_rows: None,
            probes: BTreeMap::new(),
            pair_path: String::new(),
            pair_discard: false,
            pair_outcome: None,
            publish_services: String::new(),
            publish_bind: String::new(),
            forward_route: None,
            forward_port: String::new(),
            theme,
            theme_checked: Instant::now(),
            visuals,
        })
    }

    fn busy(&self) -> bool {
        self.running > 0
    }

    fn info(&mut self, text: impl Into<String>) {
        self.notice = Some(Notice {
            text: text.into(),
            error: false,
        });
    }

    fn fail(&mut self, text: impl Into<String>) {
        self.notice = Some(Notice {
            text: text.into(),
            error: true,
        });
    }

    fn submit(&mut self, job: Job) {
        let Some(jobs) = &self.jobs else {
            return self.fail(self.locale.text(
                "El trabajador en segundo plano no está disponible.",
                "Background worker unavailable.",
            ));
        };
        if jobs.send(job).is_ok() {
            self.running += 1;
        } else {
            self.fail(self.locale.text(
                "El trabajador en segundo plano se detuvo; reinicia la aplicación.",
                "Background worker stopped; restart the application.",
            ));
        }
    }

    fn reload_local(&mut self) -> Result<()> {
        self.state = self.desktop.refresh()?;
        self.published = self.desktop.published_services().ok();
        self.routes = self.desktop.remote_routes()?;
        let choices = self.published.as_ref();
        if !choices.is_some_and(|items| items.contains(&self.selected_service)) {
            self.selected_service = choices
                .and_then(|items| items.first())
                .cloned()
                .unwrap_or_default();
        }
        if let Some(route) = &self.forward_route
            && !self
                .routes
                .iter()
                .any(|r| r.peer_id == route.0 && r.services.contains(&route.1))
        {
            self.forward_route = None;
        }
        Ok(())
    }

    fn refresh(&mut self) {
        match self.reload_local() {
            Ok(()) => self.notice = None,
            Err(_) => self.fail(self.locale.text(
                "No se pudo leer el estado; identidad sin cambios.",
                "Could not read state; identity unchanged.",
            )),
        }
        if !self.busy() {
            self.submit(Job::ScanUnits);
        }
    }

    fn issue_invite(&mut self) {
        match self
            .desktop
            .issue_invitation(&self.selected_service, Duration::from_secs(300))
        {
            Ok(receipt) => {
                self.last_invite = Some(receipt.path);
                self.info(self.locale.text(
                    "Invitación privada creada (vence en 5 minutos).",
                    "Private invitation created (expires in 5 minutes).",
                ));
                let _ = self.reload_local();
            }
            Err(_) => self.fail(self.locale.text(
                "No se pudo crear la invitación.",
                "Could not create invitation.",
            )),
        }
    }

    fn apply_confirmation(&mut self) {
        let Some(action) = self.confirmation.take() else {
            return;
        };
        let outcome = match action {
            Confirm::Approve { id, invitation, .. } => self.desktop.approve(&id, &invitation),
            Confirm::Revoke { id, .. } => self.desktop.revoke(&id),
            Confirm::Install { context, spec, .. } => {
                return self.submit(Job::Install(context, spec));
            }
            Confirm::Start(name) => return self.submit(Job::Start(name)),
            Confirm::Stop(name) => return self.submit(Job::Stop(name)),
            Confirm::Remove(name) => return self.submit(Job::Remove(name)),
        };
        match outcome {
            Ok(state) => {
                self.state = state;
                let _ = self.reload_local();
                self.info(self.locale.text(
                    "Cambio confirmado en el estado local.",
                    "Change confirmed in local state.",
                ));
            }
            Err(_) => self.fail(self.locale.text(
                "La operación no se confirmó; actualiza antes de reintentar.",
                "Operation not confirmed; refresh before retrying.",
            )),
        }
    }

    fn receive(&mut self) {
        let finished: Vec<Done> = self
            .results
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for done in finished {
            self.running = self.running.saturating_sub(1);
            let lang = self.locale;
            match done {
                Done::Pair(Ok(outcome)) => {
                    let _ = self.reload_local();
                    match outcome.status {
                        PairStatus::Pending => self.info(lang.text(
                            "Solicitud enviada: pendiente de aprobación en el otro dispositivo. Repite al aprobarse.",
                            "Request sent: pending approval on the other device. Repeat once approved.",
                        )),
                        PairStatus::Approved => self.info(lang.text(
                            "Emparejamiento aprobado; la ruta remota está disponible.",
                            "Pairing approved; the remote route is available.",
                        )),
                    }
                    self.pair_outcome = Some(outcome);
                }
                Done::Pair(Err(error)) => self.fail(format!(
                    "{}: {error}",
                    lang.text("No se pudo emparejar", "Pairing failed")
                )),
                Done::Probe { key, result } => {
                    self.probes.insert(key, result);
                }
                Done::Units(rows) => self.unit_rows = Some(rows),
                Done::UnitOp { op, name, result } => {
                    match result {
                        Ok(()) => self.info(format!(
                            "{}: {name}",
                            match op {
                                UnitOp::Install => lang.text("Unidad instalada", "Unit installed"),
                                UnitOp::Start => lang.text(
                                    "Unidad iniciada y habilitada",
                                    "Unit started and enabled"
                                ),
                                UnitOp::Stop => lang.text(
                                    "Unidad detenida y deshabilitada",
                                    "Unit stopped and disabled"
                                ),
                                UnitOp::Remove => lang.text("Unidad eliminada", "Unit removed"),
                            }
                        )),
                        Err(error) => self.fail(format!(
                            "{} {name}: {error}",
                            lang.text("Falló la unidad", "Unit operation failed for")
                        )),
                    }
                    let _ = self.reload_local();
                    self.submit(Job::ScanUnits);
                }
            }
        }
    }

    fn poll_theme(&mut self) {
        if self.theme_checked.elapsed() < Duration::from_secs(3) {
            return;
        }
        self.theme_checked = Instant::now();
        let changed = match &self.theme {
            Some(theme) => modified(&theme.source) != theme.modified,
            None => true,
        };
        if changed {
            self.theme = load_theme();
            self.visuals = visuals_for(self.theme.as_ref());
        }
    }

    fn device_section(&mut self, ui: &mut egui::Ui) {
        let lang = self.locale;
        let busy = self.busy();
        ui.heading(lang.text("Este dispositivo", "This device"));
        ui.label(format!(
            "{}: {}",
            lang.text("Nombre", "Name"),
            self.state.name
        ));
        ui.horizontal_wrapped(|ui| {
            ui.label("ID:");
            ui.monospace(&self.state.id);
            if ui
                .small_button(lang.text("Copiar ID", "Copy ID"))
                .on_hover_text(lang.text(
                    "El ID es público; no autoriza por sí solo.",
                    "The ID is public; it authorizes nothing by itself.",
                ))
                .clicked()
            {
                ui.ctx().copy_text(self.state.id.clone());
                self.info(lang.text("ID copiado.", "ID copied."));
            }
        });
        ui.add_space(12.0);
        ui.heading(lang.text("Servicios publicados", "Published services"));
        match self.published.clone() {
            Some(services) if !services.is_empty() => {
                ui.label(services.join(", "));
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("service")
                        .selected_text(&self.selected_service)
                        .show_ui(ui, |ui| {
                            for service in &services {
                                ui.selectable_value(
                                    &mut self.selected_service,
                                    service.clone(),
                                    service,
                                );
                            }
                        });
                    if ui
                        .add_enabled(
                            !busy,
                            egui::Button::new(lang.text("Crear invitación", "Create invitation")),
                        )
                        .clicked()
                    {
                        self.issue_invite();
                    }
                });
            }
            _ => {
                ui.label(lang.text(
                    "Sin publicación activa verificada. Créala en Servicios o con el CLI.",
                    "No verified active publication. Create one in Services or with the CLI.",
                ));
            }
        }
        if let Some(path) = &self.last_invite {
            ui.label(lang.text(
                "Archivo privado (0600): transfiérelo por un canal seguro.",
                "Private file (0600): transfer through a secure channel.",
            ));
            ui.monospace(path.display().to_string());
        }
    }

    fn requests_section(&mut self, ui: &mut egui::Ui) {
        let lang = self.locale;
        let busy = self.busy();
        ui.heading(format!(
            "{} ({})",
            lang.text("Solicitudes pendientes", "Pending requests"),
            self.state.pending.len()
        ));
        if self.state.pending.is_empty() {
            ui.label(lang.text("Sin solicitudes.", "No pending requests."));
        }
        let now = unix_time().unwrap_or(u64::MAX);
        for pending in &self.state.pending {
            ui.group(|ui| {
                ui.label(&pending.peer.name);
                ui.monospace(&pending.peer.id);
                let services = pending
                    .peer
                    .services
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                ui.label(format!("{}: {services}", lang.text("Permisos", "Grants")));
                if pending.expires <= now {
                    ui.label(lang.text("Expirada", "Expired"));
                } else if ui
                    .add_enabled(
                        !busy,
                        egui::Button::new(lang.text("Revisar aprobación", "Review approval")),
                    )
                    .clicked()
                {
                    self.confirmation = Some(Confirm::Approve {
                        id: pending.peer.id.clone(),
                        invitation: pending.invitation_id.clone(),
                        name: pending.peer.name.clone(),
                        services,
                    });
                }
            });
        }
    }

    fn devices_section(&mut self, ui: &mut egui::Ui) {
        let lang = self.locale;
        let busy = self.busy();
        ui.heading(lang.text("Emparejar con una invitación", "Pair with an invitation"));
        ui.label(lang.text(
            "Ruta del archivo privado (0600) recibido del otro dispositivo:",
            "Path of the private (0600) file received from the other device:",
        ));
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.pair_path)
                    .hint_text("/ruta/privada/invite.json")
                    .desired_width(380.0),
            );
            let ready = !busy && !self.pair_path.trim().is_empty();
            if ui
                .add_enabled(ready, egui::Button::new(lang.text("Emparejar", "Pair")))
                .clicked()
            {
                self.submit(Job::Pair {
                    path: PathBuf::from(self.pair_path.trim()),
                    discard: self.pair_discard,
                });
            }
        });
        ui.checkbox(
            &mut self.pair_discard,
            lang.text(
                "Eliminar el archivo cuando quede aprobado",
                "Delete the file once approved",
            ),
        );
        if let Some(outcome) = &self.pair_outcome {
            ui.group(|ui| {
                ui.label(format!(
                    "{}: {}",
                    lang.text("Estado", "Status"),
                    match outcome.status {
                        PairStatus::Pending => lang.text("pendiente", "pending"),
                        PairStatus::Approved => lang.text("aprobado", "approved"),
                    }
                ));
                ui.label(&outcome.peer_name);
                ui.monospace(&outcome.peer_id);
                if !outcome.services.is_empty() {
                    ui.label(format!(
                        "{}: {}",
                        lang.text("Servicios remotos", "Remote services"),
                        outcome.services.join(", ")
                    ));
                }
                if outcome.invite_removed {
                    ui.label(lang.text(
                        "Archivo de invitación eliminado.",
                        "Invitation file deleted.",
                    ));
                }
            });
        }
        ui.add_space(12.0);
        ui.heading(format!(
            "{} ({})",
            lang.text("Dispositivos autorizados", "Approved devices"),
            self.state.peers.len()
        ));
        if self.state.peers.is_empty() {
            ui.label(lang.text("Aún no hay dispositivos.", "No devices yet."));
        }
        for peer in &self.state.peers {
            ui.group(|ui| {
                ui.label(&peer.name);
                ui.monospace(&peer.id);
                let join = |set: &std::collections::BTreeSet<String>| {
                    set.iter().cloned().collect::<Vec<_>>().join(", ")
                };
                ui.label(format!(
                    "{}: {}",
                    lang.text("Acceso local", "Local access"),
                    join(&peer.services)
                ));
                ui.label(format!(
                    "{}: {}",
                    lang.text("Acceso remoto", "Remote access"),
                    join(&peer.remote_services)
                ));
                if ui
                    .add_enabled(
                        !busy,
                        egui::Button::new(lang.text("Revisar revocación", "Review revocation")),
                    )
                    .clicked()
                {
                    self.confirmation = Some(Confirm::Revoke {
                        id: peer.id.clone(),
                        name: peer.name.clone(),
                    });
                }
            });
        }
    }

    fn routes_section(&mut self, ui: &mut egui::Ui) {
        let lang = self.locale;
        let busy = self.busy();
        ui.heading(format!(
            "{} ({})",
            lang.text("Rutas remotas", "Remote routes"),
            self.routes.len()
        ));
        ui.label(lang.text(
            "Servicios de otros dispositivos que este dispositivo puede usar.",
            "Services on other devices that this device may use.",
        ));
        if self.routes.is_empty() {
            ui.label(lang.text(
                "Sin rutas. Empareja con una invitación en Dispositivos.",
                "No routes. Pair with an invitation in Devices.",
            ));
        }
        let mut probe = None;
        for route in &self.routes {
            ui.group(|ui| {
                ui.label(&route.peer_name);
                ui.monospace(&route.peer_id);
                if !route.has_address {
                    ui.label(lang.text("Sin dirección guardada.", "No saved address."));
                }
                for service in &route.services {
                    ui.horizontal(|ui| {
                        ui.strong(service);
                        if ui
                            .add_enabled(
                                !busy && route.has_address,
                                egui::Button::new(lang.text("Probar", "Probe")),
                            )
                            .clicked()
                        {
                            probe = Some((route.peer_id.clone(), service.clone()));
                        }
                        match self.probes.get(&(route.peer_id.clone(), service.clone())) {
                            Some(Ok(latency)) => {
                                ui.colored_label(
                                    ui.visuals().hyperlink_color,
                                    format!(
                                        "{} · {} ms",
                                        lang.text("alcanzable", "reachable"),
                                        latency.as_millis()
                                    ),
                                );
                            }
                            Some(Err(error)) => {
                                ui.colored_label(
                                    ui.visuals().error_fg_color,
                                    format!(
                                        "{}: {error}",
                                        lang.text("inalcanzable", "unreachable")
                                    ),
                                );
                            }
                            None => {}
                        }
                    });
                }
            });
        }
        if let Some((peer, service)) = probe {
            self.submit(Job::Probe { peer, service });
        }
    }

    fn prepare_install(&mut self, spec: Result<UnitSpec, &'static str>) {
        let lang = self.locale;
        let spec = match spec {
            Ok(spec) => spec,
            Err(message) => return self.fail(message),
        };
        let context = match &self.unit_context {
            Ok(context) => context.clone(),
            Err(error) => return self.fail(error.clone()),
        };
        match units::render(&context, &spec).and_then(|text| Ok((spec.unit_name()?, text))) {
            Ok((unit, text)) => {
                let exec = text
                    .lines()
                    .find_map(|line| line.strip_prefix("ExecStart="))
                    .unwrap_or_default()
                    .to_owned();
                self.confirmation = Some(Confirm::Install {
                    context,
                    spec,
                    unit,
                    exec,
                });
            }
            Err(error) => self.fail(format!(
                "{}: {}",
                lang.text("Unidad no válida", "Invalid unit"),
                shown(error)
            )),
        }
    }

    fn publish_spec(&self) -> Result<UnitSpec, &'static str> {
        let lang = self.locale;
        let invalid = lang.text(
            "Usa pares nombre=puerto (p. ej. t3=3773 api=8080) en loopback.",
            "Use name=port pairs (e.g. t3=3773 api=8080) on loopback.",
        );
        let mut services = Vec::new();
        for item in self
            .publish_services
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|item| !item.is_empty())
        {
            let (name, target) = item.split_once('=').ok_or(invalid)?;
            let target = match target.parse::<u16>() {
                Ok(port) => SocketAddr::from(([127, 0, 0, 1], port)),
                Err(_) => target.parse().map_err(|_| invalid)?,
            };
            services.push((name.to_owned(), target));
        }
        if services.is_empty() {
            return Err(invalid);
        }
        Ok(UnitSpec::Serve { services })
    }

    fn forward_spec(&self) -> Result<UnitSpec, &'static str> {
        let lang = self.locale;
        let (peer, service) = self
            .forward_route
            .clone()
            .ok_or(lang.text("Elige una ruta remota.", "Choose a remote route."))?;
        let port = self
            .forward_port
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(lang.text(
                "Indica un puerto local fijo (1-65535).",
                "Enter a fixed local port (1-65535).",
            ))?;
        Ok(UnitSpec::Forward {
            peer,
            service,
            listen: SocketAddr::from(([127, 0, 0, 1], port)),
        })
    }

    fn services_section(&mut self, ui: &mut egui::Ui) {
        let lang = self.locale;
        let busy = self.busy();
        ui.heading(lang.text("Servicios en segundo plano", "Background services"));
        ui.label(lang.text(
            "Unidades systemd --user: systemd las mantiene activas aunque cierres esta ventana.",
            "systemd --user units: systemd keeps them running after this window closes.",
        ));
        ui.label(format!(
            "{}: {}",
            lang.text("Directorio", "Directory"),
            self.units.dir().display()
        ));
        match &self.unit_context {
            Ok(context) => {
                ui.label(format!(
                    "{}: {}",
                    lang.text("Ejecutable", "Executable"),
                    context.binary.display()
                ));
            }
            Err(error) => {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    format!(
                        "{}: {error}",
                        lang.text("No se pueden crear unidades", "Cannot create units")
                    ),
                );
            }
        }
        ui.add_space(6.0);
        let mut action = None;
        match &self.unit_rows {
            None => {
                ui.label(lang.text("Consultando systemd…", "Querying systemd…"));
            }
            Some(Err(error)) => {
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
            Some(Ok(rows)) if rows.is_empty() => {
                ui.label(lang.text("No hay unidades de OmaBridge.", "No OmaBridge units."));
            }
            Some(Ok(rows)) => {
                egui::Grid::new("units")
                    .striped(true)
                    .num_columns(4)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.strong(lang.text("Unidad", "Unit"));
                        ui.strong(lang.text("Estado", "State"));
                        ui.strong(lang.text("Arranque", "Boot"));
                        ui.strong("");
                        ui.end_row();
                        for row in rows {
                            ui.monospace(&row.name);
                            let color = if row.active == "active" {
                                ui.visuals().hyperlink_color
                            } else if row.active == "failed" {
                                ui.visuals().error_fg_color
                            } else {
                                ui.visuals().weak_text_color()
                            };
                            ui.colored_label(color, &row.active);
                            ui.label(&row.enabled);
                            ui.horizontal(|ui| {
                                if !row.managed {
                                    ui.weak(
                                        lang.text("externa (solo lectura)", "external (read-only)"),
                                    );
                                    return;
                                }
                                let running = row.active == "active" || row.active == "activating";
                                if running {
                                    if ui
                                        .add_enabled(
                                            !busy,
                                            egui::Button::new(lang.text("Detener", "Stop")),
                                        )
                                        .clicked()
                                    {
                                        action = Some(Confirm::Stop(row.name.clone()));
                                    }
                                } else if ui
                                    .add_enabled(
                                        !busy,
                                        egui::Button::new(lang.text("Iniciar", "Start")),
                                    )
                                    .clicked()
                                {
                                    action = Some(Confirm::Start(row.name.clone()));
                                }
                                if ui
                                    .add_enabled(
                                        !busy,
                                        egui::Button::new(lang.text("Eliminar", "Remove")),
                                    )
                                    .clicked()
                                {
                                    action = Some(Confirm::Remove(row.name.clone()));
                                }
                            });
                            ui.end_row();
                        }
                    });
            }
        }
        if action.is_some() {
            self.confirmation = action;
        }
        let can_create = !busy && self.unit_context.is_ok();
        ui.add_space(12.0);
        ui.group(|ui| {
            ui.strong(lang.text("Publicar servicios locales", "Publish local services"));
            ui.label(lang.text(
                "Una unidad por dispositivo (omabridge-serve). Destinos solo en loopback.",
                "One unit per device (omabridge-serve). Loopback targets only.",
            ));
            ui.horizontal(|ui| {
                ui.label(lang.text("Servicios", "Services"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.publish_services)
                        .hint_text("t3=3773 api=8080")
                        .desired_width(260.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label(lang.text("Escucha QUIC (opcional)", "QUIC bind (optional)"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.publish_bind)
                        .hint_text("0.0.0.0:41234")
                        .desired_width(160.0),
                );
            });
            if ui
                .add_enabled(
                    can_create,
                    egui::Button::new(lang.text("Revisar unidad", "Review unit")),
                )
                .clicked()
            {
                let bind = self.publish_bind.trim();
                if bind.is_empty() {
                    if let Ok(context) = &mut self.unit_context {
                        context.bind = None;
                    }
                } else if let Ok(addr) = bind.parse::<SocketAddr>() {
                    if let Ok(context) = &mut self.unit_context {
                        context.bind = Some(addr);
                    }
                } else {
                    return self
                        .fail(lang.text("Dirección QUIC no válida.", "Invalid QUIC address."));
                }
                self.prepare_install(self.publish_spec());
            }
        });
        ui.add_space(6.0);
        ui.group(|ui| {
            ui.strong(lang.text("Reenviar una ruta remota", "Forward a remote route"));
            ui.label(lang.text(
                "Abre un puerto local en 127.0.0.1 hacia un servicio de otro dispositivo.",
                "Opens a local 127.0.0.1 port to a service on another device.",
            ));
            let selected = self
                .forward_route
                .as_ref()
                .map(|(peer, service)| {
                    let name = self
                        .routes
                        .iter()
                        .find(|r| &r.peer_id == peer)
                        .map(|r| r.peer_name.as_str())
                        .unwrap_or("?");
                    format!("{name} ({}…) · {service}", &peer[..8.min(peer.len())])
                })
                .unwrap_or_else(|| lang.text("Elegir ruta", "Choose route").to_owned());
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("forward_route")
                    .selected_text(selected)
                    .width(280.0)
                    .show_ui(ui, |ui| {
                        for route in &self.routes {
                            for service in &route.services {
                                let value = Some((route.peer_id.clone(), service.clone()));
                                let label = format!(
                                    "{} ({}…) · {service}",
                                    route.peer_name,
                                    &route.peer_id[..8.min(route.peer_id.len())]
                                );
                                ui.selectable_value(&mut self.forward_route, value, label);
                            }
                        }
                    });
                ui.label(lang.text("Puerto", "Port"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.forward_port)
                        .hint_text("43773")
                        .desired_width(70.0),
                );
            });
            if ui
                .add_enabled(
                    can_create && !self.routes.is_empty(),
                    egui::Button::new(lang.text("Revisar unidad", "Review unit")),
                )
                .clicked()
            {
                if let Ok(context) = &mut self.unit_context {
                    context.bind = None;
                }
                self.prepare_install(self.forward_spec());
            }
        });
    }

    fn confirmation_window(&mut self, ctx: &egui::Context) {
        let Some(action) = self.confirmation.clone() else {
            return;
        };
        let lang = self.locale;
        let mut confirm = false;
        let mut cancel = false;
        egui::Window::new(lang.text("Confirmar cambio", "Confirm change"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(560.0);
                match &action {
                    Confirm::Approve {
                        name, id, services, ..
                    } => {
                        ui.label(format!("{}: {name}", lang.text("Aprobar", "Approve")));
                        ui.monospace(id);
                        ui.label(format!("{}: {services}", lang.text("Permisos", "Grants")));
                    }
                    Confirm::Revoke { name, id } => {
                        ui.label(format!(
                            "{}: {name}",
                            lang.text("Revocar todos los permisos de", "Revoke all grants for")
                        ));
                        ui.monospace(id);
                    }
                    Confirm::Install { unit, exec, .. } => {
                        ui.label(format!(
                            "{}: {unit}",
                            lang.text(
                                "Escribir unidad (reemplaza solo si es de OmaBridge)",
                                "Write unit (replaces only an OmaBridge unit)"
                            )
                        ));
                        ui.label(lang.text("Comando:", "Command:"));
                        ui.add(egui::Label::new(RichText::new(exec).monospace()).wrap());
                        ui.label(lang.text(
                            "No se inicia hasta que pulses Iniciar.",
                            "It does not start until you press Start.",
                        ));
                    }
                    Confirm::Start(name) => {
                        ui.label(format!(
                            "{}: {name}",
                            lang.text(
                                "Iniciar y habilitar al iniciar sesión",
                                "Start and enable at login"
                            )
                        ));
                    }
                    Confirm::Stop(name) => {
                        ui.label(format!(
                            "{}: {name}",
                            lang.text("Detener y deshabilitar", "Stop and disable")
                        ));
                    }
                    Confirm::Remove(name) => {
                        ui.label(format!(
                            "{}: {name}",
                            lang.text("Detener, deshabilitar y borrar", "Stop, disable and delete")
                        ));
                    }
                }
                ui.horizontal(|ui| {
                    confirm = ui
                        .add_enabled(
                            !self.busy(),
                            egui::Button::new(lang.text("Confirmar", "Confirm")),
                        )
                        .clicked();
                    cancel = ui.button(lang.text("Cancelar", "Cancel")).clicked();
                });
            });
        if confirm {
            self.apply_confirmation();
        }
        if cancel {
            self.confirmation = None;
        }
    }
}

/// The OmaBridge mark: two square links crossed on the diagonal, each broken where
/// the other passes over it. Unlinked, both are cut where they cross and drawn muted.
const LINKED: [&[[f32; 2]]; 2] = [
    &[
        [11.4, 14.8],
        [14.8, 14.8],
        [14.8, 2.4],
        [2.4, 2.4],
        [2.4, 14.8],
        [7.0, 14.8],
    ],
    &[
        [17.0, 9.2],
        [21.6, 9.2],
        [21.6, 21.6],
        [9.2, 21.6],
        [9.2, 9.2],
        [12.6, 9.2],
    ],
];
const UNLINKED: [&[[f32; 2]]; 4] = [
    &[[11.4, 14.8], [14.8, 14.8], [14.8, 11.4]],
    &[
        [14.8, 7.0],
        [14.8, 2.4],
        [2.4, 2.4],
        [2.4, 14.8],
        [7.0, 14.8],
    ],
    &[
        [17.0, 9.2],
        [21.6, 9.2],
        [21.6, 21.6],
        [9.2, 21.6],
        [9.2, 17.0],
    ],
    &[[9.2, 12.6], [9.2, 9.2], [12.6, 9.2]],
];

fn logo(ui: &mut egui::Ui, size: f32, linked: bool) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let scale = size / 24.0;
    let color = if linked {
        ui.visuals().hyperlink_color
    } else {
        ui.visuals().weak_text_color()
    };
    let paths: &[&[[f32; 2]]] = if linked { &LINKED } else { &UNLINKED };
    for path in paths {
        let points = path
            .iter()
            .map(|[x, y]| rect.min + egui::vec2(x * scale, y * scale))
            .collect();
        ui.painter()
            .add(egui::Shape::line(points, Stroke::new(2.25 * scale, color)));
    }
}

impl eframe::App for Manager {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive();
        self.poll_theme();
        ctx.set_visuals(self.visuals.clone());
        ctx.request_repaint_after(Duration::from_secs(3));
        let lang = self.locale;
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let linked = !self.state.peers.is_empty()
                    || self
                        .published
                        .as_ref()
                        .is_some_and(|services| !services.is_empty());
                logo(ui, 20.0, linked);
                ui.heading("OmaBridge");
                ui.separator();
                ui.label(lang.text("Gestor de dispositivos", "Device manager"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(if lang == Locale::Es { "EN" } else { "ES" })
                        .clicked()
                    {
                        self.locale = if lang == Locale::Es {
                            Locale::En
                        } else {
                            Locale::Es
                        };
                    }
                    if ui.button(lang.text("Actualizar", "Refresh")).clicked() {
                        self.refresh();
                    }
                });
            });
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.busy() {
                    ui.add(egui::Spinner::new());
                    ui.label(lang.text("Trabajando…", "Working…"));
                    ui.separator();
                }
                match &self.notice {
                    Some(notice) if notice.error => {
                        ui.colored_label(ui.visuals().error_fg_color, &notice.text);
                    }
                    Some(notice) => {
                        ui.label(&notice.text);
                    }
                    None => {
                        ui.weak(lang.text("Listo.", "Ready."));
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let theme = match &self.theme {
                        Some(theme) => theme
                            .source
                            .parent()
                            .and_then(|dir| {
                                std::fs::read_to_string(dir.with_extension("name")).ok()
                            })
                            .map(|name| name.trim().chars().take(40).collect::<String>())
                            .filter(|name| !name.is_empty())
                            .unwrap_or_else(|| "Omarchy".to_owned()),
                        None => lang.text("tema oscuro", "dark theme").to_owned(),
                    };
                    ui.weak(theme);
                });
            });
        });
        let nav_fill = self
            .theme
            .as_ref()
            .map(|theme| rgb(theme.palette.panel))
            .unwrap_or_else(|| ctx.style().visuals.extreme_bg_color);
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(170.0)
            .frame(egui::Frame::side_top_panel(&ctx.style()).fill(nav_fill))
            .show(ctx, |ui| {
                ui.add_space(8.0);
                for section in Section::ALL {
                    let count = match section {
                        Section::Requests => self.state.pending.len(),
                        Section::Devices => self.state.peers.len(),
                        Section::Routes => self.routes.len(),
                        Section::Services => self
                            .unit_rows
                            .as_ref()
                            .and_then(|rows| rows.as_ref().ok())
                            .map_or(0, Vec::len),
                        Section::Device => 0,
                    };
                    let label = if count > 0 {
                        format!("{}  ({count})", section.label(lang))
                    } else {
                        section.label(lang).to_owned()
                    };
                    let text = RichText::new(label).size(15.0);
                    if ui
                        .add_sized(
                            [ui.available_width(), 30.0],
                            egui::Button::selectable(self.section == section, text),
                        )
                        .clicked()
                    {
                        self.section = section;
                    }
                }
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.section {
                Section::Device => self.device_section(ui),
                Section::Requests => self.requests_section(ui),
                Section::Devices => self.devices_section(ui),
                Section::Routes => self.routes_section(ui),
                Section::Services => self.services_section(ui),
            });
        });
        self.confirmation_window(ctx);
    }
}

fn unit_context(args: &Args, store: &Store) -> Result<UnitContext, String> {
    let binary = match &args.omabridge_bin {
        Some(path) => path.clone(),
        None => units::sibling_binary().map_err(shown)?,
    };
    if !binary.is_absolute() || !binary.is_file() {
        return Err(format!("omabridge CLI not found at {}", binary.display()));
    }
    let state_dir = std::fs::canonicalize(&args.state_dir).map_err(|e| shown(e.into()))?;
    Ok(UnitContext {
        binary,
        state_dir,
        name: store.name().map_err(shown)?,
        bind: None,
    })
}

fn run() -> Result<()> {
    let args = Args::parse();
    let store =
        Store::open(&args.state_dir, &args.name).context("cannot load OmaBridge identity")?;
    let desktop = Desktop::with_options(
        store.clone(),
        omabridge::NetOptions {
            compress_t3: false,
            bind: args.bind,
            relay: match args.relay.clone() {
                Some(relay) => relay,
                None => omabridge::Relay::load(&args.state_dir)?,
            },
        },
    );
    let units = match &args.units_dir {
        Some(dir) => Units::new(dir.clone(), std::sync::Arc::new(units::Systemctl)),
        None => Units::user()?,
    };
    if args.check {
        let public = desktop.refresh()?;
        let files = units.list()?;
        let managed = files.iter().filter(|unit| unit.managed).count();
        println!(
            "{}",
            serde_json::json!({ "id": public.id, "name": public.name,
            "peers": public.peers.len(), "pending": public.pending.len(),
            "remote_routes": desktop.remote_routes()?.len(),
            "published": desktop.published_services().unwrap_or_default(),
            "units": managed, "foreign_units": files.len() - managed })
        );
        return Ok(());
    }
    let context = unit_context(&args, &store);
    let mut manager = Manager::new(desktop.clone(), units.clone(), context)?;
    manager.section = args.section;
    let viewport = egui::ViewportBuilder::default()
        .with_app_id("omabridge-gui")
        .with_inner_size([980.0, 700.0])
        .with_min_inner_size([680.0, 460.0]);
    eframe::run_native(
        "OmaBridge",
        eframe::NativeOptions {
            viewport,
            ..Default::default()
        },
        Box::new(move |cc| {
            let (jobs, results) = spawn_worker(desktop, units, cc.egui_ctx.clone())?;
            manager.jobs = Some(jobs);
            manager.results = Some(results);
            manager.submit(Job::ScanUnits);
            Ok(Box::new(manager))
        }),
    )
    .map_err(|error| anyhow::anyhow!("could not open desktop window: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("omabridge-gui: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_labels_follow_the_selected_language() {
        assert!(matches!(Locale::from_tag("es_CL.UTF-8"), Locale::Es));
        assert!(matches!(Locale::from_tag("en_US.UTF-8"), Locale::En));
        assert_eq!(Locale::Es.text("Aprobar", "Approve"), "Aprobar");
        assert_eq!(Locale::En.text("Aprobar", "Approve"), "Approve");
        assert_eq!(Section::Routes.label(Locale::Es), "Rutas");
        assert_eq!(Section::Services.label(Locale::En), "Services");
    }

    #[test]
    fn omarchy_palette_maps_to_visuals_with_dark_fallback() {
        assert_eq!(
            visuals_for(None).panel_fill,
            egui::Visuals::dark().panel_fill
        );
        let palette = theme::parse_colors_toml(
            "background = \"#121212\"\nforeground = \"#bebebe\"\naccent = \"#e68e0d\"\nlighter_background = \"#1e1e1e\"\n",
        )
        .unwrap();
        let loaded = LoadedTheme {
            source: PathBuf::from("/x/colors.toml"),
            modified: None,
            palette,
        };
        let visuals = visuals_for(Some(&loaded));
        assert!(visuals.dark_mode);
        assert_eq!(visuals.panel_fill, Color32::from_rgb(0x12, 0x12, 0x12));
        assert_eq!(visuals.window_fill, Color32::from_rgb(0x1e, 0x1e, 0x1e));
        assert_eq!(visuals.hyperlink_color, Color32::from_rgb(0xe6, 0x8e, 0x0d));
        assert_eq!(
            visuals.widgets.noninteractive.fg_stroke.color,
            Color32::from_rgb(0xbe, 0xbe, 0xbe)
        );
    }

    #[test]
    fn errors_shown_in_the_ui_are_single_line_and_bounded() {
        let text = shown(anyhow::anyhow!("line one\nline two {}", "x".repeat(500)));
        assert!(!text.contains('\n'));
        assert_eq!(text.chars().count(), 300);
    }
}
