use eframe::egui;
use rand::Rng;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const PASSWORD_ACTIONS: [&str; 6] = [
    "configure",
    "disable",
    "install",
    "passwd",
    "uninstall",
    "unlock",
];

#[derive(Clone, Debug, Deserialize)]
struct Config {
    timezone: String,
    unlock_duration_minutes: i64,
    password_required_for: Vec<String>,
    lock_windows: Vec<LockWindow>,
}

#[derive(Clone, Debug, Deserialize)]
struct LockWindow {
    start: String,
    end: String,
    days: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct StatusPayload {
    allowed: bool,
    reason: String,
    locked_until: Option<String>,
    unlock_expires_at: Option<String>,
}

#[derive(Clone, Debug)]
struct WindowDraft {
    start: String,
    end: String,
    days: [bool; 7],
}

impl Default for WindowDraft {
    fn default() -> Self {
        Self {
            start: "19:00".to_owned(),
            end: "05:00".to_owned(),
            days: [true; 7],
        }
    }
}

impl WindowDraft {
    fn from_window(window: &LockWindow) -> Self {
        let mut days = [false; 7];
        for day in &window.days {
            if let Some(index) = DAYS.iter().position(|value| value == day) {
                days[index] = true;
            }
        }
        Self {
            start: window.start.clone(),
            end: window.end.clone(),
            days,
        }
    }

    fn to_cli_value(&self) -> Result<String, String> {
        if self.start == self.end {
            return Err("Lock window start and end cannot be the same.".to_owned());
        }
        let days: Vec<&str> = DAYS
            .iter()
            .enumerate()
            .filter_map(|(index, day)| self.days[index].then_some(*day))
            .collect();
        if days.is_empty() {
            return Err("Each lock window needs at least one day.".to_owned());
        }
        Ok(format!("{}-{} {}", self.start, self.end, days.join(",")))
    }
}

#[derive(Default)]
struct PasswordFields {
    current: String,
    new_first: String,
    new_again: String,
    setup_first: String,
    setup_again: String,
    unlock: String,
}

struct PromptParoleApp {
    cli_path: PathBuf,
    app_dir: PathBuf,
    config: Config,
    configured: bool,
    status: Option<StatusPayload>,
    status_line: String,
    error: String,
    passwords: PasswordFields,
    windows: Vec<WindowDraft>,
    timezone: String,
    unlock_duration_minutes: i64,
    unlock_request_minutes: i64,
    password_actions: Vec<String>,
    generated_password: String,
}

impl PromptParoleApp {
    fn new() -> Self {
        let cli_path = find_cli_path();
        let app_dir = app_dir();
        let mut app = Self {
            cli_path,
            app_dir,
            config: default_config(),
            configured: false,
            status: None,
            status_line: "Loading status".to_owned(),
            error: String::new(),
            passwords: PasswordFields::default(),
            windows: vec![WindowDraft::default()],
            timezone: "local".to_owned(),
            unlock_duration_minutes: 30,
            unlock_request_minutes: 30,
            password_actions: PASSWORD_ACTIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            generated_password: String::new(),
        };
        app.reload();
        app
    }

    fn reload(&mut self) {
        self.configured = self.app_dir.join("secret.json").exists();
        self.config = read_config(&self.app_dir).unwrap_or_else(default_config);
        self.timezone = self.config.timezone.clone();
        self.unlock_duration_minutes = self.config.unlock_duration_minutes;
        self.unlock_request_minutes = self.config.unlock_duration_minutes;
        self.password_actions = normalized_actions(&self.config.password_required_for);
        self.windows = if self.config.lock_windows.is_empty() {
            vec![WindowDraft::default()]
        } else {
            self.config
                .lock_windows
                .iter()
                .map(WindowDraft::from_window)
                .collect()
        };
        self.status = self.fetch_status().ok();
        self.status_line = match (&self.status, self.configured) {
            (_, false) => "Not configured".to_owned(),
            (Some(status), _) if status.allowed => format!("Allowed: {}", status.reason),
            (Some(status), _) => format!("Blocked: {}", status.reason),
            (None, _) => "Configured; status unavailable".to_owned(),
        };
    }

    fn fetch_status(&self) -> Result<StatusPayload, String> {
        let output = self.run_cli(["status", "--json"], "")?;
        serde_json::from_str(&output).map_err(|err| format!("Could not parse status: {err}"))
    }

    fn run_cli<I, S>(&self, args: I, stdin: &str) -> Result<String, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut command = Command::new(&self.cli_path);
        for arg in args {
            command.arg(arg.as_ref());
        }
        if stdin.is_empty() {
            command.stdin(Stdio::null());
        } else {
            command.stdin(Stdio::piped());
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|err| {
            format!(
                "Could not run {}: {err}. Set PROMPT_PAROLE_CLI to the prompt-parole executable.",
                self.cli_path.display()
            )
        })?;
        if !stdin.is_empty() {
            use std::io::Write;
            let mut handle = child
                .stdin
                .take()
                .ok_or_else(|| "Could not open CLI stdin.".to_owned())?;
            handle
                .write_all(stdin.as_bytes())
                .map_err(|err| format!("Could not write password input: {err}"))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|err| format!("CLI did not finish: {err}"))?;
        if output.status.success() {
            String::from_utf8(output.stdout)
                .map_err(|err| format!("CLI output was not UTF-8: {err}"))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            Err(if stderr.is_empty() { stdout } else { stderr })
        }
    }

    fn setup(&mut self) {
        self.error.clear();
        if self.passwords.setup_first != self.passwords.setup_again {
            self.error = "Passwords do not match.".to_owned();
            return;
        }
        let window_args = match self.window_args() {
            Ok(args) => args,
            Err(err) => {
                self.error = err;
                return;
            }
        };
        let mut args = vec![
            "setup".to_owned(),
            "--password-stdin".to_owned(),
            "--timezone".to_owned(),
            self.timezone.clone(),
            "--unlock-duration-minutes".to_owned(),
            self.unlock_duration_minutes.to_string(),
            "--password-required-for".to_owned(),
            self.password_actions.join(","),
        ];
        args.extend(window_args);
        let stdin = format!(
            "{}\n{}\n",
            self.passwords.setup_first, self.passwords.setup_again
        );
        match self.run_cli(args.iter().map(String::as_str), &stdin) {
            Ok(_) => {
                self.passwords.setup_first.clear();
                self.passwords.setup_again.clear();
                self.generated_password.clear();
                self.reload();
                self.status_line = "Prompt Parole is set up.".to_owned();
            }
            Err(err) => self.error = err,
        }
    }

    fn save_settings(&mut self) {
        self.error.clear();
        let window_args = match self.window_args() {
            Ok(args) => args,
            Err(err) => {
                self.error = err;
                return;
            }
        };
        let mut args = vec![
            "configure".to_owned(),
            "--password-stdin".to_owned(),
            "--timezone".to_owned(),
            self.timezone.clone(),
            "--unlock-duration-minutes".to_owned(),
            self.unlock_duration_minutes.to_string(),
            "--password-required-for".to_owned(),
            self.password_actions.join(","),
        ];
        args.extend(window_args);
        let stdin = format!("{}\n", self.passwords.current);
        match self.run_cli(args.iter().map(String::as_str), &stdin) {
            Ok(_) => {
                self.passwords.current.clear();
                self.reload();
                self.status_line = "Settings saved.".to_owned();
            }
            Err(err) => self.error = err,
        }
    }

    fn unlock(&mut self) {
        self.error.clear();
        let args = [
            "unlock",
            "--password-stdin",
            "--duration-minutes",
            &self.unlock_request_minutes.to_string(),
        ];
        let stdin = format!("{}\n", self.passwords.unlock);
        match self.run_cli(args, &stdin) {
            Ok(output) => {
                self.passwords.unlock.clear();
                self.reload();
                self.status_line = output.trim().to_owned();
            }
            Err(err) => self.error = err,
        }
    }

    fn change_password(&mut self) {
        self.error.clear();
        if self.passwords.new_first != self.passwords.new_again {
            self.error = "Passwords do not match.".to_owned();
            return;
        }
        let stdin = format!(
            "{}\n{}\n{}\n",
            self.passwords.current, self.passwords.new_first, self.passwords.new_again
        );
        match self.run_cli(["passwd", "--password-stdin"], &stdin) {
            Ok(_) => {
                self.passwords.current.clear();
                self.passwords.new_first.clear();
                self.passwords.new_again.clear();
                self.generated_password.clear();
                self.reload();
                self.status_line = "Password changed.".to_owned();
            }
            Err(err) => self.error = err,
        }
    }

    fn manual_lock(&mut self) {
        self.error.clear();
        match self.run_cli(["lock"], "") {
            Ok(_) => {
                self.reload();
                self.status_line = "Temporary unlock cleared.".to_owned();
            }
            Err(err) => self.error = err,
        }
    }

    fn window_args(&self) -> Result<Vec<String>, String> {
        if self.windows.is_empty() {
            return Err("At least one lock window is required.".to_owned());
        }
        let mut args = Vec::new();
        for window in &self.windows {
            args.push("--lock-window".to_owned());
            args.push(window.to_cli_value()?);
        }
        Ok(args)
    }

    fn suggest_password(&mut self) {
        let value = generate_password();
        self.generated_password = value.clone();
        if self.configured {
            self.passwords.new_first = value.clone();
            self.passwords.new_again = value;
        } else {
            self.passwords.setup_first = value.clone();
            self.passwords.setup_again = value;
        }
    }
}

impl eframe::App for PromptParoleApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        apply_style(ui.ctx());
        egui::Frame::new()
            .fill(shironeri())
            .inner_margin(22)
            .show(ui, |ui| {
                app_header(ui, &self.status_line, self.configured);
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if primary_button(ui, "Refresh").clicked() {
                        self.reload();
                    }
                    ui.label(
                        egui::RichText::new(format!("CLI {}", self.cli_path.display()))
                            .color(rikyunezumi())
                            .size(13.0),
                    );
                });
                if !self.error.is_empty() {
                    ui.add_space(10.0);
                    alert_frame().show(ui, |ui| {
                        ui.colored_label(enji(), egui::RichText::new(&self.error).strong());
                    });
                }
                ui.add_space(14.0);

                if self.configured {
                    egui::ScrollArea::vertical().show(ui, |ui| self.configured_ui(ui));
                } else {
                    egui::ScrollArea::vertical().show(ui, |ui| self.setup_ui(ui));
                }
            });
    }
}

impl PromptParoleApp {
    fn setup_ui(&mut self, ui: &mut egui::Ui) {
        section_frame().show(ui, |ui| {
            section_title(ui, "First Setup");
            form_grid(ui, "setup-passwords", |ui| {
                password_editor(ui, "Password", &mut self.passwords.setup_first);
                password_editor(ui, "Password again", &mut self.passwords.setup_again);
            });
            password_suggestion(ui, self);
            ui.add_space(8.0);
            settings_editor(
                ui,
                &mut self.timezone,
                &mut self.unlock_duration_minutes,
                &mut self.windows,
                &mut self.password_actions,
            );
            ui.add_space(10.0);
            if primary_button(ui, "Start Parole").clicked() {
                self.setup();
            }
        });
    }

    fn configured_ui(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |columns| {
            section_frame().show(&mut columns[0], |ui| {
                section_title(ui, "Settings");
                form_grid(ui, "current-password", |ui| {
                    password_editor(ui, "Current password", &mut self.passwords.current);
                });
                settings_editor(
                    ui,
                    &mut self.timezone,
                    &mut self.unlock_duration_minutes,
                    &mut self.windows,
                    &mut self.password_actions,
                );
                ui.add_space(10.0);
                if primary_button(ui, "Save Settings").clicked() {
                    self.save_settings();
                }
            });

            columns[1].vertical(|ui| {
                section_frame().show(ui, |ui| {
                    section_title(ui, "Unlock");
                    form_grid(ui, "unlock-form", |ui| {
                        password_editor(ui, "Password", &mut self.passwords.unlock);
                        ui.label("Duration");
                        ui.add(
                            egui::DragValue::new(&mut self.unlock_request_minutes)
                                .range(1..=1440)
                                .suffix(" min"),
                        );
                    });
                    if primary_button(ui, "Unlock Temporarily").clicked() {
                        self.unlock();
                    }

                    if let Some(status) = &self.status {
                        if let Some(value) = &status.locked_until {
                            meta_label(ui, format!("Scheduled lock ends: {value}"));
                        }
                        if let Some(value) = &status.unlock_expires_at {
                            meta_label(ui, format!("Temporary unlock expires: {value}"));
                        }
                    }
                });

                ui.add_space(14.0);
                section_frame().show(ui, |ui| {
                    section_title(ui, "Password");
                    form_grid(ui, "change-password", |ui| {
                        password_editor(ui, "New password", &mut self.passwords.new_first);
                        password_editor(ui, "New password again", &mut self.passwords.new_again);
                    });
                    password_suggestion(ui, self);
                    if primary_button(ui, "Change Password").clicked() {
                        self.change_password();
                    }
                });

                ui.add_space(14.0);
                section_frame().show(ui, |ui| {
                    section_title(ui, "Manual Lock");
                    if secondary_button(ui, "Clear Temporary Unlock").clicked() {
                        self.manual_lock();
                    }
                });
            });
        });
    }
}

fn settings_editor(
    ui: &mut egui::Ui,
    timezone: &mut String,
    unlock_duration_minutes: &mut i64,
    windows: &mut Vec<WindowDraft>,
    password_actions: &mut Vec<String>,
) {
    subsection_title(ui, "Lock Windows");
    let mut remove_index = None;
    let time_options = time_options(windows);
    let can_remove = windows.len() > 1;
    for (index, window) in windows.iter_mut().enumerate() {
        lock_window_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(format!("Window {}", index + 1))
                        .strong()
                        .color(sumi()),
                );
                egui::ComboBox::from_id_salt(format!("start-{index}"))
                    .selected_text(&window.start)
                    .width(86.0)
                    .show_ui(ui, |ui| {
                        for option in &time_options {
                            ui.selectable_value(&mut window.start, option.clone(), option);
                        }
                    });
                ui.label("to");
                egui::ComboBox::from_id_salt(format!("end-{index}"))
                    .selected_text(&window.end)
                    .width(86.0)
                    .show_ui(ui, |ui| {
                        for option in &time_options {
                            ui.selectable_value(&mut window.end, option.clone(), option);
                        }
                    });
                if can_remove && secondary_button(ui, "Remove").clicked() {
                    remove_index = Some(index);
                }
            });
            ui.horizontal_wrapped(|ui| {
                for (day_index, day) in DAYS.iter().enumerate() {
                    ui.checkbox(&mut window.days[day_index], *day);
                }
            });
        });
    }
    if let Some(index) = remove_index {
        windows.remove(index);
    }
    if secondary_button(ui, "Add Lock Window").clicked() {
        windows.push(WindowDraft::default());
    }

    ui.add_space(14.0);
    subsection_title(ui, "General");
    form_grid(ui, "general-settings", |ui| {
        ui.label("Timezone");
        ui.add(egui::TextEdit::singleline(timezone).desired_width(180.0));
        ui.label("Default unlock");
        ui.add(
            egui::DragValue::new(unlock_duration_minutes)
                .range(1..=1440)
                .suffix(" min"),
        );
    });
    meta_label(ui, "Password required for");
    ui.horizontal_wrapped(|ui| {
        for action in PASSWORD_ACTIONS {
            let mut enabled = password_actions.iter().any(|value| value == action);
            if ui.checkbox(&mut enabled, action).changed() {
                if enabled {
                    password_actions.push(action.to_owned());
                    password_actions.sort();
                    password_actions.dedup();
                } else {
                    password_actions.retain(|value| value != action);
                }
            }
        }
    });
}

fn password_editor(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .desired_width(230.0),
    );
}

fn password_suggestion(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    ui.horizontal_wrapped(|ui| {
        if secondary_button(ui, "Suggest Local Password").clicked() {
            app.suggest_password();
        }
        if !app.generated_password.is_empty() {
            ui.label(
                egui::RichText::new(&app.generated_password)
                    .monospace()
                    .color(aomidori())
                    .strong(),
            );
        }
    });
    meta_label(
        ui,
        "No recovery command. Keep the password somewhere recoverable.",
    );
}

fn app_header(ui: &mut egui::Ui, status: &str, configured: bool) {
    ui.horizontal(|ui| {
        ui.heading(
            egui::RichText::new("Prompt Parole")
                .size(30.0)
                .color(sumi())
                .strong(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            status_pill(ui, status, configured);
        });
    });
    ui.add_space(10.0);
    palette_strip(ui);
}

fn palette_strip(ui: &mut egui::Ui) {
    let colors = [
        shironeri(),
        torinoko(),
        seiji(),
        aomidori(),
        asagi(),
        yamabuki(),
        enji(),
        sumi(),
    ];
    let available = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(available, 8.0), egui::Sense::hover());
    let width = rect.width() / colors.len() as f32;
    for (index, color) in colors.iter().enumerate() {
        let min = egui::pos2(rect.min.x + width * index as f32, rect.min.y);
        let max = egui::pos2(rect.min.x + width * (index + 1) as f32, rect.max.y);
        ui.painter()
            .rect_filled(egui::Rect::from_min_max(min, max), 0.0, *color);
    }
}

fn status_pill(ui: &mut egui::Ui, status: &str, configured: bool) {
    let fill = if configured { aomidori() } else { yamabuki() };
    let text_color = if configured { button_fg() } else { sumi() };
    egui::Frame::new()
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(16))
        .inner_margin(egui::Margin::symmetric(12, 6))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(status)
                    .color(text_color)
                    .strong()
                    .size(13.5),
            );
        });
}

fn section_title(ui: &mut egui::Ui, title: &str) {
    ui.label(egui::RichText::new(title).size(20.0).strong().color(sumi()));
    ui.add_space(8.0);
}

fn subsection_title(ui: &mut egui::Ui, title: &str) {
    ui.label(
        egui::RichText::new(title)
            .size(15.0)
            .strong()
            .color(aomidori()),
    );
    ui.add_space(4.0);
}

fn meta_label(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(
        egui::RichText::new(text.into())
            .color(rikyunezumi())
            .size(13.0),
    );
}

fn form_grid(ui: &mut egui::Ui, id: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing(egui::vec2(12.0, 8.0))
        .min_col_width(118.0)
        .show(ui, add_contents);
}

fn section_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(panel())
        .stroke(egui::Stroke::new(1.0, line()))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(16))
}

fn lock_window_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(field())
        .stroke(egui::Stroke::new(1.0, line()))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(10))
}

fn alert_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(torinoko())
        .stroke(egui::Stroke::new(1.5, enji()))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(10))
}

fn primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .color(button_fg())
                .strong()
                .size(14.0),
        )
        .fill(aomidori())
        .stroke(egui::Stroke::new(1.0, aomidori()))
        .corner_radius(egui::CornerRadius::same(6))
        .min_size(egui::vec2(120.0, 34.0)),
    )
}

fn secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .color(aomidori())
                .strong()
                .size(14.0),
        )
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, aomidori()))
        .corner_radius(egui::CornerRadius::same(6))
        .min_size(egui::vec2(96.0, 32.0)),
    )
}

fn time_options(windows: &[WindowDraft]) -> Vec<String> {
    let mut options = Vec::new();
    for hour in 0..24 {
        for minute in [0, 15, 30, 45] {
            options.push(format!("{hour:02}:{minute:02}"));
        }
    }
    for window in windows {
        if !options.contains(&window.start) {
            options.push(window.start.clone());
        }
        if !options.contains(&window.end) {
            options.push(window.end.clone());
        }
    }
    options.sort();
    options
}

fn generate_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rng();
    let mut out = String::new();
    for index in 0..20 {
        if index > 0 && index % 5 == 0 {
            out.push('-');
        }
        let pos = rng.random_range(0..ALPHABET.len());
        out.push(ALPHABET[pos] as char);
    }
    out
}

fn normalized_actions(actions: &[String]) -> Vec<String> {
    let mut values: Vec<String> = PASSWORD_ACTIONS
        .iter()
        .filter(|action| actions.iter().any(|value| value == **action))
        .map(|value| (*value).to_owned())
        .collect();
    if values.is_empty() {
        values = PASSWORD_ACTIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
    }
    values
}

fn read_config(app_dir: &Path) -> Option<Config> {
    let path = app_dir.join("config.json");
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn default_config() -> Config {
    Config {
        timezone: "local".to_owned(),
        unlock_duration_minutes: 30,
        password_required_for: PASSWORD_ACTIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        lock_windows: vec![LockWindow {
            start: "19:00".to_owned(),
            end: "05:00".to_owned(),
            days: DAYS.iter().map(|value| (*value).to_owned()).collect(),
        }],
    }
}

fn app_dir() -> PathBuf {
    if let Ok(value) = env::var("PROMPT_PAROLE_HOME") {
        return PathBuf::from(value);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".prompt-parole")
}

fn find_cli_path() -> PathBuf {
    if let Ok(value) = env::var("PROMPT_PAROLE_CLI") {
        return PathBuf::from(value);
    }
    if let Some(home) = dirs::home_dir() {
        let local = home.join(".local").join("bin").join(if cfg!(windows) {
            "prompt-parole.exe"
        } else {
            "prompt-parole"
        });
        if local.exists() {
            return local;
        }
    }
    PathBuf::from(if cfg!(windows) {
        "prompt-parole.exe"
    } else {
        "prompt-parole"
    })
}

fn apply_style(ctx: &egui::Context) {
    let mut style = (*ctx.global_style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(24.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(15.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.interact_size = egui::vec2(40.0, 32.0);

    let mut visuals = egui::Visuals::light();
    visuals.override_text_color = Some(sumi());
    visuals.panel_fill = shironeri();
    visuals.window_fill = shironeri();
    visuals.faint_bg_color = panel();
    visuals.extreme_bg_color = field();
    visuals.selection.bg_fill = asagi();
    visuals.selection.stroke = egui::Stroke::new(1.0, sumi());
    visuals.widgets.noninteractive.bg_fill = panel();
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, sumi());
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, line());
    visuals.widgets.inactive.bg_fill = field();
    visuals.widgets.inactive.weak_bg_fill = field();
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, line());
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, sumi());
    visuals.widgets.hovered.bg_fill = torinoko();
    visuals.widgets.hovered.weak_bg_fill = torinoko();
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, asagi());
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, sumi());
    visuals.widgets.active.bg_fill = seiji();
    visuals.widgets.active.weak_bg_fill = seiji();
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, aomidori());
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, sumi());
    visuals.window_stroke = egui::Stroke::new(1.0, line());
    style.visuals = visuals;
    ctx.set_global_style(style);
}

fn shironeri() -> egui::Color32 {
    egui::Color32::from_rgb(255, 221, 202)
}

fn torinoko() -> egui::Color32 {
    egui::Color32::from_rgb(226, 190, 159)
}

fn seiji() -> egui::Color32 {
    egui::Color32::from_rgb(129, 156, 139)
}

fn aomidori() -> egui::Color32 {
    egui::Color32::from_rgb(58, 105, 96)
}

fn asagi() -> egui::Color32 {
    egui::Color32::from_rgb(72, 146, 155)
}

fn yamabuki() -> egui::Color32 {
    egui::Color32::from_rgb(255, 164, 0)
}

fn enji() -> egui::Color32 {
    egui::Color32::from_rgb(157, 41, 51)
}

fn sumi() -> egui::Color32 {
    egui::Color32::from_rgb(39, 34, 31)
}

fn rikyunezumi() -> egui::Color32 {
    egui::Color32::from_rgb(101, 98, 85)
}

fn panel() -> egui::Color32 {
    egui::Color32::from_rgb(255, 238, 226)
}

fn field() -> egui::Color32 {
    egui::Color32::from_rgb(255, 248, 241)
}

fn line() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(57, 52, 50, 58)
}

fn button_fg() -> egui::Color32 {
    egui::Color32::from_rgb(255, 255, 251)
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Prompt Parole")
            .with_inner_size([920.0, 760.0])
            .with_min_inner_size([680.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Prompt Parole",
        options,
        Box::new(|_| Ok(Box::new(PromptParoleApp::new()))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_draft_builds_cli_value() {
        let mut draft = WindowDraft::default();
        draft.days = [true, true, false, false, false, false, false];
        assert_eq!(draft.to_cli_value().unwrap(), "19:00-05:00 mon,tue");
    }

    #[test]
    fn window_draft_rejects_no_days() {
        let mut draft = WindowDraft::default();
        draft.days = [false; 7];
        assert!(
            draft
                .to_cli_value()
                .unwrap_err()
                .contains("at least one day")
        );
    }

    #[test]
    fn generated_password_is_not_tiny() {
        let password = generate_password();
        assert_eq!(password.len(), 23);
        assert!(
            password
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || value == '-')
        );
    }

    #[test]
    fn nippon_palette_values_are_stable() {
        assert_eq!(shironeri(), egui::Color32::from_rgb(255, 221, 202));
        assert_eq!(torinoko(), egui::Color32::from_rgb(226, 190, 159));
        assert_eq!(seiji(), egui::Color32::from_rgb(129, 156, 139));
        assert_eq!(aomidori(), egui::Color32::from_rgb(58, 105, 96));
        assert_eq!(asagi(), egui::Color32::from_rgb(72, 146, 155));
        assert_eq!(yamabuki(), egui::Color32::from_rgb(255, 164, 0));
        assert_eq!(enji(), egui::Color32::from_rgb(157, 41, 51));
        assert_eq!(sumi(), egui::Color32::from_rgb(39, 34, 31));
    }
}
