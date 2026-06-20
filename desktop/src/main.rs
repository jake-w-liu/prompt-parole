use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Datelike, Duration, Local, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use clap::{Parser, Subcommand, ValueEnum};
use constant_time_eq::constant_time_eq;
use eframe::egui;
use rand::Rng;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration as StdDuration;

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const PASSWORD_ACTIONS: [&str; 6] = [
    "configure",
    "disable",
    "install",
    "passwd",
    "uninstall",
    "unlock",
];
const HARD_PASSWORD_ACTIONS: [&str; 3] = ["configure", "passwd", "unlock"];

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Config {
    version: i64,
    timezone: String,
    unlock_duration_minutes: i64,
    password_required_for: Vec<String>,
    lock_windows: Vec<LockWindow>,
    log_prompt_text: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LockWindow {
    start: String,
    end: String,
    days: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StatusPayload {
    allowed: bool,
    scheduled_locked: bool,
    temporarily_unlocked: bool,
    reason: String,
    locked_until: Option<String>,
    unlock_expires_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GuardStatus {
    locked: bool,
    target_focused: bool,
    blocking_input: bool,
    foreground: String,
    detail: String,
}

#[derive(Clone, Debug)]
struct Decision {
    allowed: bool,
    scheduled_locked: bool,
    temporarily_unlocked: bool,
    reason: String,
    locked_until: Option<DateTime<chrono::FixedOffset>>,
    unlock_expires_at: Option<DateTime<chrono::FixedOffset>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct State {
    version: i64,
    unlock_expires_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Secret {
    version: i64,
    kdf: String,
    params: SecretParams,
    salt: String,
    hash: String,
    created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SecretParams {
    n: u32,
    r: u32,
    p: u32,
    dklen: usize,
}

#[derive(Clone)]
struct ParoleCore {
    app_dir: PathBuf,
}

impl ParoleCore {
    fn config_path(&self) -> PathBuf {
        self.app_dir.join("config.json")
    }

    fn secret_path(&self) -> PathBuf {
        self.app_dir.join("secret.json")
    }

    fn state_path(&self) -> PathBuf {
        self.app_dir.join("state.json")
    }

    fn events_path(&self) -> PathBuf {
        self.app_dir.join("events.jsonl")
    }

    fn is_configured(&self) -> bool {
        self.secret_path().exists()
    }

    fn load_config(&self) -> Result<Config, String> {
        if !self.config_path().exists() {
            return Ok(default_config());
        }
        let raw = fs::read_to_string(self.config_path())
            .map_err(|err| format!("Could not read config: {err}"))?;
        let config: Config =
            serde_json::from_str(&raw).map_err(|err| format!("Config is invalid JSON: {err}"))?;
        normalize_config(config)
    }

    fn load_state(&self) -> State {
        let path = self.state_path();
        if let Ok(raw) = fs::read_to_string(path)
            && let Ok(state) = serde_json::from_str(&raw)
        {
            return state;
        }
        State {
            version: 1,
            unlock_expires_at: None,
            updated_at: None,
        }
    }

    fn load_secret(&self) -> Result<Secret, String> {
        let raw = fs::read_to_string(self.secret_path())
            .map_err(|_| "Prompt Parole is not configured.".to_owned())?;
        serde_json::from_str(&raw).map_err(|err| format!("Password file is invalid: {err}"))
    }

    fn setup(
        &self,
        password: &str,
        windows: Vec<String>,
        timezone: String,
        unlock_duration_minutes: i64,
        password_required_for: Vec<String>,
    ) -> Result<(), String> {
        if self.is_configured() {
            return Err(
                "Prompt Parole is already configured. Use passwd to change the password."
                    .to_owned(),
            );
        }
        let secret = hash_password(password)?;
        let config = config_from_parts(
            windows,
            timezone,
            unlock_duration_minutes,
            password_required_for,
        )?;
        write_json_atomic(&self.config_path(), &config)?;
        write_json_atomic(&self.secret_path(), &secret)?;
        let state = State {
            version: 1,
            unlock_expires_at: None,
            updated_at: Some(now_iso()),
        };
        write_json_atomic(&self.state_path(), &state)?;
        append_event(&self.events_path(), serde_json::json!({"event": "setup"}));
        Ok(())
    }

    fn assert_password(&self, password: &str) -> Result<(), String> {
        if verify_password(password, &self.load_secret()?)? {
            Ok(())
        } else {
            Err("Incorrect password.".to_owned())
        }
    }

    fn configure(
        &self,
        current_password: &str,
        windows: Vec<String>,
        timezone: String,
        unlock_duration_minutes: i64,
        password_required_for: Vec<String>,
    ) -> Result<Config, String> {
        self.assert_password(current_password)?;
        let config = config_from_parts(
            windows,
            timezone,
            unlock_duration_minutes,
            password_required_for,
        )?;
        write_json_atomic(&self.config_path(), &config)?;
        append_event(
            &self.events_path(),
            serde_json::json!({"event": "configured"}),
        );
        Ok(config)
    }

    fn change_password(&self, current_password: &str, new_password: &str) -> Result<(), String> {
        self.assert_password(current_password)?;
        let secret = hash_password(new_password)?;
        write_json_atomic(&self.secret_path(), &secret)?;
        append_event(
            &self.events_path(),
            serde_json::json!({"event": "password_changed"}),
        );
        Ok(())
    }

    fn unlock(
        &self,
        password: &str,
        duration_minutes: i64,
    ) -> Result<DateTime<chrono::FixedOffset>, String> {
        self.assert_password(password)?;
        if duration_minutes <= 0 {
            return Err("Unlock duration must be positive.".to_owned());
        }
        let config = self.load_config()?;
        let expires = now_for_config(&config)? + Duration::minutes(duration_minutes);
        let state = State {
            version: 1,
            unlock_expires_at: Some(expires.to_rfc3339()),
            updated_at: Some(now_iso()),
        };
        write_json_atomic(&self.state_path(), &state)?;
        append_event(
            &self.events_path(),
            serde_json::json!({"event": "unlocked", "duration_minutes": duration_minutes}),
        );
        Ok(expires)
    }

    fn lock(&self) -> Result<(), String> {
        let state = State {
            version: 1,
            unlock_expires_at: None,
            updated_at: Some(now_iso()),
        };
        write_json_atomic(&self.state_path(), &state)?;
        append_event(
            &self.events_path(),
            serde_json::json!({"event": "manually_locked"}),
        );
        Ok(())
    }

    fn status(&self) -> Result<StatusPayload, String> {
        if !self.is_configured() {
            return Err("Prompt Parole is not configured.".to_owned());
        }
        let decision = self.decision()?;
        Ok(StatusPayload {
            allowed: decision.allowed,
            scheduled_locked: decision.scheduled_locked,
            temporarily_unlocked: decision.temporarily_unlocked,
            reason: decision.reason,
            locked_until: decision.locked_until.map(|value| value.to_rfc3339()),
            unlock_expires_at: decision.unlock_expires_at.map(|value| value.to_rfc3339()),
        })
    }

    fn decision(&self) -> Result<Decision, String> {
        evaluate(&self.load_config()?, &self.load_state())
    }

    fn hook_payload(&self, agent: &str) -> Result<Option<serde_json::Value>, String> {
        let agent = normalized_hook_agent(agent)?;
        if !self.is_configured() {
            return Ok(None);
        }
        let decision = self.decision()?;
        if decision.allowed {
            return Ok(None);
        }
        append_event(
            &self.events_path(),
            serde_json::json!({"event": "prompt_blocked", "agent": agent}),
        );
        let until = decision
            .locked_until
            .map(|value| value.format("%Y-%m-%d %H:%M %Z").to_string())
            .unwrap_or_else(|| "the scheduled unlock time".to_owned());
        let mut payload = serde_json::json!({
            "decision": "block",
            "reason": format!("Prompt Parole: curfew is active until {until}. You can inspect progress, but new prompts need `prompt-parole unlock`.")
        });
        if agent == "claude-code" {
            payload["suppressOriginalPrompt"] = serde_json::Value::Bool(true);
        }
        Ok(Some(payload))
    }
}

fn normalized_hook_agent(agent: &str) -> Result<&'static str, String> {
    match agent {
        "codex" => Ok("codex"),
        "claude" | "claude-code" => Ok("claude-code"),
        _ => Err(format!("Unsupported agent {agent:?}.")),
    }
}

fn config_from_parts(
    windows: Vec<String>,
    timezone: String,
    unlock_duration_minutes: i64,
    password_required_for: Vec<String>,
) -> Result<Config, String> {
    let lock_windows = if windows.is_empty() {
        default_config().lock_windows
    } else {
        windows
            .iter()
            .map(|value| parse_window(value))
            .collect::<Result<Vec<_>, _>>()?
    };
    normalize_config(Config {
        version: 1,
        timezone,
        unlock_duration_minutes,
        password_required_for,
        lock_windows,
        log_prompt_text: false,
    })
}

fn normalize_config(mut config: Config) -> Result<Config, String> {
    if config.lock_windows.is_empty() {
        return Err("At least one lock window is required.".to_owned());
    }
    for window in &config.lock_windows {
        parse_hhmm(&window.start)?;
        parse_hhmm(&window.end)?;
        if window.start == window.end {
            return Err("Lock window start and end cannot be the same.".to_owned());
        }
        if window.days.is_empty() {
            return Err("Lock window days must be non-empty.".to_owned());
        }
        for day in &window.days {
            if !DAYS.contains(&day.as_str()) {
                return Err(format!("Invalid day {day:?}."));
            }
        }
    }
    if config.unlock_duration_minutes <= 0 {
        return Err("unlock_duration_minutes must be positive.".to_owned());
    }
    if config.timezone != "local" {
        config
            .timezone
            .parse::<Tz>()
            .map_err(|_| format!("Unknown timezone {:?}.", config.timezone))?;
    }
    let mut actions: BTreeSet<String> = HARD_PASSWORD_ACTIONS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    for action in &config.password_required_for {
        if !PASSWORD_ACTIONS.contains(&action.as_str()) {
            return Err(format!("Invalid password action {action:?}."));
        }
        actions.insert(action.clone());
    }
    config.version = 1;
    config.password_required_for = actions.into_iter().collect();
    Ok(config)
}

fn parse_window(value: &str) -> Result<LockWindow, String> {
    let mut parts = value.split_whitespace();
    let time_part = parts
        .next()
        .ok_or_else(|| "Lock window must look like HH:MM-HH:MM.".to_owned())?;
    let (start, end) = time_part
        .split_once('-')
        .ok_or_else(|| "Lock window must look like HH:MM-HH:MM.".to_owned())?;
    parse_hhmm(start)?;
    parse_hhmm(end)?;
    if start == end {
        return Err("Lock window start and end cannot be the same.".to_owned());
    }
    let day_part = parts.collect::<Vec<_>>().join(" ");
    let days = if day_part.trim().is_empty() {
        DAYS.iter().map(|value| (*value).to_owned()).collect()
    } else {
        day_part
            .replace(';', ",")
            .split(',')
            .filter_map(|day| {
                let clean = day.trim().to_lowercase();
                (!clean.is_empty()).then_some(clean)
            })
            .collect()
    };
    Ok(LockWindow {
        start: start.to_owned(),
        end: end.to_owned(),
        days,
    })
}

fn parse_hhmm(value: &str) -> Result<NaiveTime, String> {
    NaiveTime::parse_from_str(value, "%H:%M")
        .map_err(|_| format!("Invalid time {value:?}; expected HH:MM."))
}

fn now_for_config(config: &Config) -> Result<DateTime<chrono::FixedOffset>, String> {
    if config.timezone == "local" {
        return Ok(Local::now().fixed_offset());
    }
    let tz = config
        .timezone
        .parse::<Tz>()
        .map_err(|_| format!("Unknown timezone {:?}.", config.timezone))?;
    Ok(Utc::now().with_timezone(&tz).fixed_offset())
}

fn evaluate(config: &Config, state: &State) -> Result<Decision, String> {
    let now = now_for_config(config)?;
    let locked_until = scheduled_lock_until(config, now)?;
    let unlock_expires_at = state
        .unlock_expires_at
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
    let scheduled_locked = locked_until.is_some();
    let temporarily_unlocked = unlock_expires_at.is_some_and(|value| now < value);
    if !scheduled_locked {
        return Ok(Decision {
            allowed: true,
            scheduled_locked: false,
            temporarily_unlocked,
            reason: "outside lock window".to_owned(),
            locked_until: None,
            unlock_expires_at,
        });
    }
    if temporarily_unlocked {
        return Ok(Decision {
            allowed: true,
            scheduled_locked: true,
            temporarily_unlocked: true,
            reason: "temporarily unlocked".to_owned(),
            locked_until,
            unlock_expires_at,
        });
    }
    Ok(Decision {
        allowed: false,
        scheduled_locked: true,
        temporarily_unlocked: false,
        reason: "prompt curfew active".to_owned(),
        locked_until,
        unlock_expires_at,
    })
}

fn scheduled_lock_until(
    config: &Config,
    now: DateTime<chrono::FixedOffset>,
) -> Result<Option<DateTime<chrono::FixedOffset>>, String> {
    let mut matching = Vec::new();
    for window in &config.lock_windows {
        for offset in [-1, 0] {
            let start_date = now.date_naive() + Duration::days(offset);
            let day = DAYS[start_date.weekday().num_days_from_monday() as usize];
            if !window.days.iter().any(|value| value == day) {
                continue;
            }
            let start_time = parse_hhmm(&window.start)?;
            let end_time = parse_hhmm(&window.end)?;
            let start_naive = start_date.and_time(start_time);
            let mut end_naive = start_date.and_time(end_time);
            if end_naive <= start_naive {
                end_naive += Duration::days(1);
            }
            let start_dt = now
                .offset()
                .from_local_datetime(&start_naive)
                .single()
                .ok_or_else(|| "Could not resolve lock start time.".to_owned())?;
            let end_dt = now
                .offset()
                .from_local_datetime(&end_naive)
                .single()
                .ok_or_else(|| "Could not resolve lock end time.".to_owned())?;
            if start_dt <= now && now < end_dt {
                matching.push(end_dt);
            }
        }
    }
    Ok(matching.into_iter().max())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.trim().is_empty() {
        Err("Password cannot be empty or only whitespace.".to_owned())
    } else {
        Ok(())
    }
}

fn hash_password(password: &str) -> Result<Secret, String> {
    validate_password(password)?;
    let mut salt = [0_u8; 16];
    rand::rng().fill(&mut salt);
    let mut output = vec![0_u8; 32];
    let params =
        ScryptParams::new(15, 8, 1, 32).map_err(|err| format!("Invalid scrypt params: {err}"))?;
    scrypt(password.as_bytes(), &salt, &params, &mut output)
        .map_err(|err| format!("Could not hash password: {err}"))?;
    Ok(Secret {
        version: 1,
        kdf: "scrypt".to_owned(),
        params: SecretParams {
            n: 2_u32.pow(15),
            r: 8,
            p: 1,
            dklen: 32,
        },
        salt: general_purpose::STANDARD.encode(salt),
        hash: general_purpose::STANDARD.encode(output),
        created_at: now_iso(),
    })
}

fn verify_password(password: &str, secret: &Secret) -> Result<bool, String> {
    if secret.kdf != "scrypt" {
        return Ok(false);
    }
    let log_n = secret
        .params
        .n
        .checked_ilog2()
        .ok_or_else(|| "Invalid scrypt n parameter.".to_owned())? as u8;
    if 2_u32.pow(log_n as u32) != secret.params.n {
        return Err("Invalid scrypt n parameter.".to_owned());
    }
    let salt = general_purpose::STANDARD
        .decode(&secret.salt)
        .map_err(|err| format!("Invalid password salt: {err}"))?;
    let expected = general_purpose::STANDARD
        .decode(&secret.hash)
        .map_err(|err| format!("Invalid password hash: {err}"))?;
    let params = ScryptParams::new(log_n, secret.params.r, secret.params.p, secret.params.dklen)
        .map_err(|err| format!("Invalid scrypt params: {err}"))?;
    let mut output = vec![0_u8; secret.params.dklen];
    scrypt(password.as_bytes(), &salt, &params, &mut output)
        .map_err(|err| format!("Could not verify password: {err}"))?;
    Ok(constant_time_eq(&output, &expected))
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|err| format!("Could not create {}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("Could not secure {}: {err}", path.display()))?;
    }
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory.", path.display()))?;
    ensure_private_dir(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("Could not create temp file for {}: {err}", path.display()))?;
    serde_json::to_writer_pretty(&mut temp, value)
        .map_err(|err| format!("Could not write JSON: {err}"))?;
    temp.write_all(b"\n")
        .map_err(|err| format!("Could not finish JSON: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("Could not secure temp file: {err}"))?;
    }
    temp.persist(path)
        .map_err(|err| format!("Could not replace {}: {}", path.display(), err.error))?;
    Ok(())
}

fn append_event(path: &Path, payload: serde_json::Value) {
    if let Some(parent) = path.parent()
        && ensure_private_dir(parent).is_err()
    {
        return;
    }
    let mut event = serde_json::Map::new();
    event.insert("ts".to_owned(), serde_json::Value::String(now_iso()));
    if let serde_json::Value::Object(map) = payload {
        event.extend(map);
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{}", serde_json::Value::Object(event));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
    }
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
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
    settings_current: String,
    install_current: String,
    change_current: String,
    new_first: String,
    new_again: String,
    setup_first: String,
    setup_again: String,
    unlock: String,
}

#[derive(Clone, Debug, Default)]
struct ProtectionStatus {
    codex_hook: bool,
    claude_hook: bool,
    codex_launcher: bool,
    claude_launcher: bool,
    codex_path_uses_launcher: bool,
    claude_path_uses_launcher: bool,
    input_guard_running: bool,
    mac_app_installed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppTab {
    Status,
    Schedule,
    Unlock,
    Password,
    Protection,
}

impl AppTab {
    const ALL: [Self; 5] = [
        Self::Status,
        Self::Schedule,
        Self::Unlock,
        Self::Password,
        Self::Protection,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Status => "Status",
            Self::Schedule => "Schedule",
            Self::Unlock => "Unlock",
            Self::Password => "Password",
            Self::Protection => "Protection",
        }
    }

    fn from_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "status" => Some(Self::Status),
            "schedule" => Some(Self::Schedule),
            "unlock" => Some(Self::Unlock),
            "password" => Some(Self::Password),
            "protection" => Some(Self::Protection),
            _ => None,
        }
    }
}

struct PromptParoleApp {
    core: ParoleCore,
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
    protection: ProtectionStatus,
    active_tab: AppTab,
    viewport_normalized: bool,
}

impl PromptParoleApp {
    fn new() -> Self {
        let app_dir = app_dir();
        let core = ParoleCore {
            app_dir: app_dir.clone(),
        };
        let mut app = Self {
            core,
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
            protection: ProtectionStatus::default(),
            active_tab: initial_app_tab(),
            viewport_normalized: false,
        };
        app.reload();
        app
    }

    fn reload(&mut self) {
        self.configured = self.app_dir.join("secret.json").exists();
        self.config = self.core.load_config().unwrap_or_else(|_| default_config());
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
        self.status = self.core.status().ok();
        self.protection = protection_status();
        self.status_line = match (&self.status, self.configured) {
            (_, false) => "Not configured".to_owned(),
            (Some(status), _) if status.allowed => format!("Allowed: {}", status.reason),
            (Some(status), _) => format!("Blocked: {}", status.reason),
            (None, _) => "Configured; status unavailable".to_owned(),
        };
    }

    fn setup(&mut self) {
        self.error.clear();
        if self.passwords.setup_first != self.passwords.setup_again {
            self.error = "Passwords do not match.".to_owned();
            return;
        }
        let windows = match self.window_values() {
            Ok(values) => values,
            Err(err) => {
                self.error = err;
                return;
            }
        };
        match self.core.setup(
            &self.passwords.setup_first,
            windows,
            self.timezone.clone(),
            self.unlock_duration_minutes,
            self.password_actions.clone(),
        ) {
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
        let windows = match self.window_values() {
            Ok(values) => values,
            Err(err) => {
                self.error = err;
                return;
            }
        };
        match self.core.configure(
            &self.passwords.settings_current,
            windows,
            self.timezone.clone(),
            self.unlock_duration_minutes,
            self.password_actions.clone(),
        ) {
            Ok(_) => {
                self.passwords.settings_current.clear();
                self.reload();
                self.status_line = "Settings saved.".to_owned();
            }
            Err(err) => self.error = err,
        }
    }

    fn unlock(&mut self) {
        self.error.clear();
        match self
            .core
            .unlock(&self.passwords.unlock, self.unlock_request_minutes)
        {
            Ok(expires) => {
                self.passwords.unlock.clear();
                self.reload();
                self.status_line = format!("Unlocked until {}.", expires.to_rfc3339());
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
        match self
            .core
            .change_password(&self.passwords.change_current, &self.passwords.new_first)
        {
            Ok(_) => {
                self.passwords.change_current.clear();
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
        match self.core.lock() {
            Ok(_) => {
                self.reload();
                self.status_line = "Temporary unlock cleared.".to_owned();
            }
            Err(err) => self.error = err,
        }
    }

    fn install_protection(&mut self) {
        self.error.clear();
        if let Err(err) = self.core.assert_password(&self.passwords.install_current) {
            self.error = err;
            return;
        }
        let mut installed = 0;
        for target in ["claude", "codex"] {
            let path = match target_path(target, None) {
                Ok(path) => path,
                Err(err) => {
                    self.error = err;
                    return;
                }
            };
            let command = default_hook_command(&target_agent(target));
            if let Err(err) = install_json_hook(&path, &command, "Checking Prompt Parole curfew") {
                self.error = err;
                return;
            }
            if let Err(err) = install_launcher(target, None) {
                self.error = err;
                return;
            }
            installed += 1;
        }
        self.passwords.install_current.clear();
        self.status_line = format!("Installed hooks and launchers for {installed} tools.");
        self.reload();
    }

    fn start_input_guard(&mut self) {
        self.error.clear();
        match start_guard_agent(&self.core) {
            Ok(()) => {
                self.status_line = "Input guard started.".to_owned();
                thread::sleep(StdDuration::from_millis(500));
                self.reload();
            }
            Err(err) => {
                self.error = format!("Could not start input guard: {err}");
            }
        }
    }

    fn install_app_bundle(&mut self) {
        self.error.clear();
        match install_macos_app_bundle(None) {
            Ok(path) => {
                self.status_line = format!("Installed app at {}.", path.display());
                self.reload();
            }
            Err(err) => {
                self.error = format!("Could not install app: {err}");
            }
        }
    }

    fn window_values(&self) -> Result<Vec<String>, String> {
        if self.windows.is_empty() {
            return Err("At least one lock window is required.".to_owned());
        }
        let mut values = Vec::new();
        for window in &self.windows {
            values.push(window.to_cli_value()?);
        }
        Ok(values)
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
        if !self.viewport_normalized {
            normalize_gui_viewport(ui.ctx());
            self.viewport_normalized = true;
        }
        egui::Frame::new()
            .fill(shironeri())
            .inner_margin(0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        centered_page(ui, |ui| {
                            app_header(ui, &self.status_line, self.configured);
                            ui.add_space(18.0);
                            if !self.error.is_empty() {
                                ui.add_space(12.0);
                                alert_frame().show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.colored_label(
                                        enji(),
                                        egui::RichText::new(&self.error).strong().size(14.0),
                                    );
                                });
                            }
                            ui.add_space(18.0);

                            if self.configured {
                                self.configured_ui(ui);
                            } else {
                                self.setup_ui(ui);
                            }
                        });
                    });
            });
    }
}

fn normalize_gui_viewport(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(
        620.0, 400.0,
    )));
    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(760.0, 460.0)));
    ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(
        120.0, 90.0,
    )));
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
}

impl PromptParoleApp {
    fn setup_ui(&mut self, ui: &mut egui::Ui) {
        let wide = ui.available_width() >= 900.0;
        if wide {
            ui.horizontal_top(|ui| {
                ui.set_width(ui.available_width());
                ui.vertical(|ui| {
                    ui.set_width(340.0);
                    setup_password_card(ui, self);
                });
                ui.add_space(16.0);
                ui.vertical(|ui| {
                    ui.set_width(ui.available_width());
                    schedule_settings_card(ui, self, true);
                });
            });
        } else {
            setup_password_card(ui, self);
            ui.add_space(14.0);
            schedule_settings_card(ui, self, true);
        }
    }

    fn configured_ui(&mut self, ui: &mut egui::Ui) {
        tab_bar(ui, &mut self.active_tab);
        ui.add_space(14.0);
        match self.active_tab {
            AppTab::Status => overview_card(ui, self),
            AppTab::Schedule => schedule_settings_card(ui, self, false),
            AppTab::Unlock => {
                unlock_card(ui, self);
                ui.add_space(14.0);
                manual_lock_card(ui, self);
            }
            AppTab::Password => password_card(ui, self),
            AppTab::Protection => protection_card(ui, self),
        }
    }
}

fn tab_bar(ui: &mut egui::Ui, active_tab: &mut AppTab) {
    egui::Frame::new()
        .fill(panel())
        .stroke(egui::Stroke::new(1.0, line()))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(6))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                for tab in AppTab::ALL {
                    let selected = *active_tab == tab;
                    let fill = if selected {
                        aomidori()
                    } else {
                        egui::Color32::TRANSPARENT
                    };
                    let text_color = if selected { button_fg() } else { aomidori() };
                    let response = ui.add(
                        egui::Button::new(
                            egui::RichText::new(tab.label())
                                .size(13.5)
                                .strong()
                                .color(text_color),
                        )
                        .fill(fill)
                        .stroke(egui::Stroke::new(1.0, aomidori()))
                        .corner_radius(egui::CornerRadius::same(6))
                        .min_size(egui::vec2(96.0, 32.0)),
                    );
                    if response.clicked() {
                        *active_tab = tab;
                    }
                }
            });
        });
}

fn setup_password_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "First Setup");
        vertical_password_editor(ui, "Password", &mut app.passwords.setup_first);
        ui.add_space(8.0);
        vertical_password_editor(ui, "Password again", &mut app.passwords.setup_again);
        ui.add_space(12.0);
        password_suggestion(ui, app);
        ui.add_space(16.0);
        if full_primary_button(ui, "Start Parole").clicked() {
            app.setup();
        }
    });
}

fn overview_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width((ui.available_width() - 20.0).max(320.0) * 0.55);
                section_title(ui, "Prompt State");
                if let Some(status) = &app.status {
                    status_summary(ui, status);
                }
                meta_label(ui, format!("Config {}", app.app_dir.display()));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                if secondary_button(ui, "Refresh").clicked() {
                    app.reload();
                }
                if primary_button(ui, "Start Input Guard").clicked() {
                    app.start_input_guard();
                }
            });
        });
    });
}

fn schedule_settings_card(ui: &mut egui::Ui, app: &mut PromptParoleApp, setup: bool) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(
            ui,
            if setup {
                "Lock Schedule"
            } else {
                "Schedule & Settings"
            },
        );
        settings_editor(
            ui,
            &mut app.timezone,
            &mut app.unlock_duration_minutes,
            &mut app.windows,
            &mut app.password_actions,
        );
        if !setup {
            ui.add_space(16.0);
            vertical_password_editor(
                ui,
                "Password for settings",
                &mut app.passwords.settings_current,
            );
            ui.add_space(10.0);
            if full_primary_button(ui, "Save Settings").clicked() {
                app.save_settings();
            }
        }
    });
}

fn unlock_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Temporary Unlock");
        vertical_password_editor(ui, "Password", &mut app.passwords.unlock);
        ui.add_space(8.0);
        labeled_drag_value(ui, "Duration", &mut app.unlock_request_minutes);
        ui.add_space(14.0);
        if full_primary_button(ui, "Unlock Temporarily").clicked() {
            app.unlock();
        }
        if let Some(status) = &app.status {
            ui.add_space(10.0);
            if let Some(value) = &status.locked_until {
                meta_label(ui, format!("Scheduled lock ends: {value}"));
            }
            if let Some(value) = &status.unlock_expires_at {
                meta_label(ui, format!("Temporary unlock expires: {value}"));
            }
        }
    });
}

fn password_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Password");
        vertical_password_editor(ui, "Current password", &mut app.passwords.change_current);
        ui.add_space(8.0);
        vertical_password_editor(ui, "New password", &mut app.passwords.new_first);
        ui.add_space(8.0);
        vertical_password_editor(ui, "New password again", &mut app.passwords.new_again);
        ui.add_space(12.0);
        password_suggestion(ui, app);
        ui.add_space(10.0);
        if full_primary_button(ui, "Change Password").clicked() {
            app.change_password();
        }
    });
}

fn manual_lock_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Manual Lock");
        if full_secondary_button(ui, "Clear Temporary Unlock").clicked() {
            app.manual_lock();
        }
    });
}

fn protection_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Protection");
        protection_summary(ui, &app.protection);
        ui.add_space(12.0);
        vertical_password_editor(
            ui,
            "Password for install",
            &mut app.passwords.install_current,
        );
        ui.add_space(10.0);
        if full_secondary_button(ui, "Install Hooks & Launchers").clicked() {
            app.install_protection();
        }
        meta_label(ui, "Protect future Codex and Claude sessions.");
        ui.add_space(8.0);
        if full_secondary_button(ui, "Install Mac App").clicked() {
            app.install_app_bundle();
        }
        meta_label(ui, "Add Prompt Parole to your Applications folder.");
    });
}

fn centered_page(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    let max_width = 720.0;
    let horizontal_margin = 18.0;
    let target_width = (ui.available_width() - horizontal_margin * 2.0)
        .max(320.0)
        .min(max_width);
    ui.horizontal(|ui| {
        let side = ((ui.available_width() - target_width) / 2.0).max(0.0);
        ui.add_space(side);
        ui.vertical(|ui| {
            ui.set_width(target_width);
            ui.add_space(18.0);
            add_contents(ui);
            ui.add_space(22.0);
        });
    });
}

fn vertical_password_editor(ui: &mut egui::Ui, label: &str, value: &mut String) {
    field_label(ui, label);
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .desired_width(ui.available_width()),
    );
}

fn labeled_drag_value(ui: &mut egui::Ui, label: &str, value: &mut i64) {
    field_label(ui, label);
    ui.add(
        egui::DragValue::new(value)
            .range(1..=1440)
            .suffix(" min")
            .speed(5),
    );
}

fn field_label(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .size(13.0)
            .strong()
            .color(rikyunezumi()),
    );
}

fn full_primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add_sized(
        [ui.available_width(), 36.0],
        egui::Button::new(
            egui::RichText::new(label)
                .color(button_fg())
                .strong()
                .size(14.0),
        )
        .fill(aomidori())
        .stroke(egui::Stroke::new(1.0, aomidori()))
        .corner_radius(egui::CornerRadius::same(6)),
    )
}

fn full_secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add_sized(
        [ui.available_width(), 34.0],
        egui::Button::new(
            egui::RichText::new(label)
                .color(aomidori())
                .strong()
                .size(14.0),
        )
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, aomidori()))
        .corner_radius(egui::CornerRadius::same(6)),
    )
}

fn compact_secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .color(aomidori())
                .strong()
                .size(13.0),
        )
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, aomidori()))
        .corner_radius(egui::CornerRadius::same(6))
        .min_size(egui::vec2(72.0, 28.0)),
    )
}

fn settings_editor(
    ui: &mut egui::Ui,
    timezone: &mut String,
    unlock_duration_minutes: &mut i64,
    windows: &mut Vec<WindowDraft>,
    password_actions: &mut Vec<String>,
) {
    subsection_title(ui, "Global Curfew");
    let mut remove_index = None;
    let time_options = time_options(windows);
    let can_remove = windows.len() > 1;
    for (index, window) in windows.iter_mut().enumerate() {
        lock_window_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                let label = if index == 0 {
                    "Curfew".to_owned()
                } else {
                    format!("Extra range {}", index + 1)
                };
                ui.label(egui::RichText::new(label).strong().color(sumi()));
                ui.add_space(6.0);
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
                if can_remove && compact_secondary_button(ui, "Remove").clicked() {
                    remove_index = Some(index);
                }
            });
            ui.add_space(8.0);
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
    ui.add_space(8.0);
    if full_secondary_button(ui, "Add Time Range").clicked() {
        windows.push(WindowDraft::default());
    }

    ui.add_space(18.0);
    subsection_title(ui, "General");
    ui.horizontal_wrapped(|ui| {
        ui.vertical(|ui| {
            ui.set_width(220.0);
            field_label(ui, "Timezone");
            ui.add(egui::TextEdit::singleline(timezone).desired_width(200.0));
        });
        ui.add_space(10.0);
        ui.vertical(|ui| {
            ui.set_width(180.0);
            labeled_drag_value(ui, "Default unlock", unlock_duration_minutes);
        });
    });
    ui.add_space(14.0);
    subsection_title(ui, "Password Gates");
    ui.horizontal_wrapped(|ui| {
        for action in PASSWORD_ACTIONS {
            let mut enabled = password_actions.iter().any(|value| value == action);
            let hard_required = HARD_PASSWORD_ACTIONS.contains(&action);
            if hard_required {
                enabled = true;
            }
            let changed = ui
                .add_enabled(!hard_required, egui::Checkbox::new(&mut enabled, action))
                .changed();
            if changed && !hard_required {
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
                .size(26.0)
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

fn status_summary(ui: &mut egui::Ui, status: &StatusPayload) {
    let (label, color) = if status.allowed {
        ("PROMPTS ALLOWED", aomidori())
    } else {
        ("PROMPTS BLOCKED", enji())
    };
    ui.label(egui::RichText::new(label).size(18.0).strong().color(color));
    meta_label(ui, status.reason.as_str());
    if let Some(value) = &status.locked_until {
        meta_label(ui, format!("Lock ends {value}"));
    }
    if let Some(value) = &status.unlock_expires_at {
        meta_label(ui, format!("Temporary unlock until {value}"));
    }
}

fn protection_summary(ui: &mut egui::Ui, protection: &ProtectionStatus) {
    protection_status_row(
        ui,
        "Open Codex/Claude windows",
        protection.input_guard_running.then_some("Protected"),
        Some("Needs start"),
    );
    protection_status_row(
        ui,
        "Codex prompt blocking",
        protection
            .codex_hook
            .then_some("Ready after restart")
            .or(Some("Needs install")),
        None,
    );
    protection_command_row(
        ui,
        "Codex command launch",
        protection.codex_launcher,
        protection.codex_path_uses_launcher,
    );
    protection_status_row(
        ui,
        "Claude prompt blocking",
        protection
            .claude_hook
            .then_some("Ready after restart")
            .or(Some("Needs install")),
        None,
    );
    protection_command_row(
        ui,
        "Claude command launch",
        protection.claude_launcher,
        protection.claude_path_uses_launcher,
    );
    protection_status_row(
        ui,
        "Mac app menu",
        protection.mac_app_installed.then_some("Installed"),
        Some("Needs install"),
    );
}

fn protection_command_row(ui: &mut egui::Ui, label: &str, launcher: bool, path_ready: bool) {
    let status = protection_command_status(launcher, path_ready);
    protection_status_row(ui, label, Some(status), None);
}

fn protection_command_status(launcher: bool, path_ready: bool) -> &'static str {
    if path_ready {
        "Protected"
    } else if launcher {
        "Not first in PATH"
    } else {
        "Needs install"
    }
}

fn protection_status_row(
    ui: &mut egui::Ui,
    label: &str,
    positive_status: Option<&str>,
    fallback_status: Option<&str>,
) {
    let status = positive_status.unwrap_or_else(|| fallback_status.unwrap_or("Off"));
    let color = match status {
        "Protected" | "Installed" | "Ready after restart" => aomidori(),
        "Not first in PATH" => yamabuki(),
        _ => enji(),
    };
    ui.horizontal(|ui| {
        ui.set_height(24.0);
        ui.label(egui::RichText::new(label).strong().color(sumi()).size(13.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            status_badge(ui, status, color);
        });
    });
}

fn status_badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    let text_color = if color == yamabuki() {
        sumi()
    } else {
        button_fg()
    };
    egui::Frame::new()
        .fill(color)
        .corner_radius(egui::CornerRadius::same(12))
        .inner_margin(egui::Margin::symmetric(9, 4))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(text)
                    .size(11.5)
                    .strong()
                    .color(text_color),
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

fn initial_app_tab() -> AppTab {
    env::var("PROMPT_PAROLE_INITIAL_TAB")
        .ok()
        .and_then(|value| AppTab::from_name(&value))
        .unwrap_or(AppTab::Status)
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

fn default_config() -> Config {
    Config {
        version: 1,
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
        log_prompt_text: false,
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
    egui::Color32::from_rgb(252, 250, 242)
}

fn torinoko() -> egui::Color32 {
    egui::Color32::from_rgb(249, 191, 69)
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
    egui::Color32::from_rgb(255, 255, 251)
}

fn field() -> egui::Color32 {
    egui::Color32::from_rgb(246, 251, 247)
}

fn line() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(57, 52, 50, 58)
}

fn button_fg() -> egui::Color32 {
    egui::Color32::from_rgb(255, 255, 251)
}

#[derive(Parser)]
#[command(
    name = "prompt-parole",
    version,
    about = "Prompt curfew for Claude Code and Codex."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CommandKind>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum GuardAgentAction {
    Start,
    Stop,
    Status,
}

#[derive(Subcommand)]
enum CommandKind {
    Setup {
        #[arg(long)]
        password_stdin: bool,
        #[arg(long = "lock-window")]
        lock_window: Vec<String>,
        #[arg(long, default_value = "local")]
        timezone: String,
        #[arg(long, default_value_t = 30)]
        unlock_duration_minutes: i64,
        #[arg(long)]
        password_required_for: Option<String>,
    },
    Configure {
        #[arg(long)]
        password_stdin: bool,
        #[arg(long = "lock-window")]
        lock_window: Vec<String>,
        #[arg(long)]
        timezone: Option<String>,
        #[arg(long)]
        unlock_duration_minutes: Option<i64>,
        #[arg(long)]
        password_required_for: Option<String>,
    },
    Passwd {
        #[arg(long)]
        password_stdin: bool,
    },
    Unlock {
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        duration_minutes: Option<i64>,
    },
    Lock,
    Status {
        #[arg(long)]
        json: bool,
    },
    Check {
        #[arg(long)]
        json: bool,
    },
    Hook {
        #[arg(long)]
        agent: String,
    },
    Guard {
        #[arg(long)]
        once: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 150)]
        poll_millis: u64,
    },
    GuardAgent {
        #[arg(long, value_enum, default_value = "start")]
        action: GuardAgentAction,
    },
    #[command(hide = true)]
    GuardWatchdog {
        #[arg(long, default_value_t = 5)]
        interval_seconds: u64,
    },
    Install {
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, default_value = "claude,codex")]
        targets: String,
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long)]
        hook_command: Option<String>,
    },
    InstallLaunchers {
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, default_value = "claude,codex")]
        targets: String,
        #[arg(long)]
        bin_dir: Option<PathBuf>,
    },
    UninstallLaunchers {
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, default_value = "claude,codex")]
        targets: String,
        #[arg(long)]
        bin_dir: Option<PathBuf>,
    },
    InstallApp {
        #[arg(long)]
        app_dir: Option<PathBuf>,
    },
    Launch {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        real: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
    Uninstall {
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, default_value = "claude,codex")]
        targets: String,
        #[arg(long)]
        home: Option<PathBuf>,
    },
    Gui,
}

fn run_cli(command: CommandKind, core: &ParoleCore) -> Result<i32, String> {
    match command {
        CommandKind::Setup {
            password_stdin,
            lock_window,
            timezone,
            unlock_duration_minutes,
            password_required_for,
        } => {
            let (first, second) = read_new_password(password_stdin)?;
            if first != second {
                return Err("Passwords do not match.".to_owned());
            }
            core.setup(
                &first,
                lock_window,
                timezone,
                unlock_duration_minutes,
                action_list(password_required_for),
            )?;
            println!("Prompt Parole is set up.");
            Ok(0)
        }
        CommandKind::Configure {
            password_stdin,
            lock_window,
            timezone,
            unlock_duration_minutes,
            password_required_for,
        } => {
            let current = read_current_password(password_stdin, "Current password: ")?;
            let existing = core.load_config()?;
            let windows = if lock_window.is_empty() {
                existing
                    .lock_windows
                    .iter()
                    .map(window_to_cli_value)
                    .collect::<Vec<_>>()
            } else {
                lock_window
            };
            let config = core.configure(
                &current,
                windows,
                timezone.unwrap_or(existing.timezone),
                unlock_duration_minutes.unwrap_or(existing.unlock_duration_minutes),
                password_required_for
                    .map(|value| action_list(Some(value)))
                    .unwrap_or(existing.password_required_for),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&config).map_err(|err| err.to_string())?
            );
            Ok(0)
        }
        CommandKind::Passwd { password_stdin } => {
            let (current, first, second) = read_password_change(password_stdin)?;
            if first != second {
                return Err("Passwords do not match.".to_owned());
            }
            core.change_password(&current, &first)?;
            println!("Password changed.");
            Ok(0)
        }
        CommandKind::Unlock {
            password_stdin,
            duration_minutes,
        } => {
            let password = read_current_password(password_stdin, "Password: ")?;
            let minutes = duration_minutes.unwrap_or(core.load_config()?.unlock_duration_minutes);
            let expires = core.unlock(&password, minutes)?;
            println!("Unlocked until {}.", expires.format("%Y-%m-%d %H:%M:%S %Z"));
            Ok(0)
        }
        CommandKind::Lock => {
            core.lock()?;
            println!("Locked.");
            Ok(0)
        }
        CommandKind::Status { json } => {
            let status = core.status()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&status).map_err(|err| err.to_string())?
                );
            } else {
                println!(
                    "Prompts are {}: {}.",
                    if status.allowed { "allowed" } else { "blocked" },
                    status.reason
                );
                if let Some(value) = status.locked_until {
                    println!("Scheduled lock ends: {value}");
                }
                if let Some(value) = status.unlock_expires_at {
                    println!("Temporary unlock expires: {value}");
                }
            }
            Ok(0)
        }
        CommandKind::Check { json } => {
            let status = core.status()?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"allowed": status.allowed, "reason": status.reason})
                );
            } else {
                println!("{}", if status.allowed { "allowed" } else { "blocked" });
            }
            Ok(if status.allowed { 0 } else { 1 })
        }
        CommandKind::Hook { agent } => {
            match core.hook_payload(&agent) {
                Ok(Some(payload)) => println!("{}", payload),
                Ok(None) => {}
                Err(err) => {
                    println!(
                        "{}",
                        serde_json::json!({"decision": "block", "reason": format!("Prompt Parole configuration error: {err}")})
                    );
                }
            }
            Ok(0)
        }
        CommandKind::Guard {
            once,
            json,
            poll_millis,
        } => {
            if once {
                let status = input_guard_status(core)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string(&status).map_err(|err| err.to_string())?
                    );
                } else {
                    println!(
                        "{}: {} ({})",
                        if status.blocking_input {
                            "blocking"
                        } else {
                            "not blocking"
                        },
                        status.foreground,
                        status.detail
                    );
                }
                return Ok(if status.blocking_input { 1 } else { 0 });
            }
            run_input_guard(core.clone(), poll_millis)
        }
        CommandKind::GuardAgent { action } => {
            match action {
                GuardAgentAction::Start => {
                    start_guard_agent(core)?;
                    println!("Input guard agent started.");
                }
                GuardAgentAction::Stop => {
                    stop_guard_agent(core)?;
                    println!("Input guard agent stopped.");
                }
                GuardAgentAction::Status => {
                    println!(
                        "{}",
                        if input_guard_running() {
                            "running"
                        } else {
                            "stopped"
                        }
                    );
                }
            }
            Ok(0)
        }
        CommandKind::GuardWatchdog { interval_seconds } => {
            run_guard_watchdog(core.clone(), interval_seconds)
        }
        CommandKind::Install {
            password_stdin,
            targets,
            home,
            hook_command,
        } => {
            require_action_password(core, password_stdin, "install")?;
            for target in parse_targets(&targets)? {
                let path = target_path(&target, home.as_deref())?;
                let command = hook_command
                    .clone()
                    .unwrap_or_else(|| default_hook_command(&target_agent(&target)));
                let backup = install_json_hook(&path, &command, "Checking Prompt Parole curfew")?;
                if let Some(path) = backup {
                    println!("Installed {target} hook. backup: {}", path.display());
                } else {
                    println!("Installed {target} hook.");
                }
            }
            Ok(0)
        }
        CommandKind::InstallLaunchers {
            password_stdin,
            targets,
            bin_dir,
        } => {
            require_action_password(core, password_stdin, "install")?;
            for target in parse_targets(&targets)? {
                let report = install_launcher(&target, bin_dir.as_deref())?;
                if let Some(backup) = report.backup {
                    println!(
                        "Installed {target} launcher at {}. backup: {}",
                        report.wrapper.display(),
                        backup.display()
                    );
                } else {
                    println!(
                        "Installed {target} launcher at {}.",
                        report.wrapper.display()
                    );
                }
            }
            Ok(0)
        }
        CommandKind::UninstallLaunchers {
            password_stdin,
            targets,
            bin_dir,
        } => {
            require_action_password(core, password_stdin, "uninstall")?;
            for target in parse_targets(&targets)? {
                let restored = uninstall_launcher(&target, bin_dir.as_deref())?;
                if let Some(path) = restored {
                    println!("Removed {target} launcher and restored {}.", path.display());
                } else {
                    println!("Removed {target} launcher.");
                }
            }
            Ok(0)
        }
        CommandKind::InstallApp { app_dir } => {
            let path = install_macos_app_bundle(app_dir.as_deref())?;
            println!("Installed Prompt Parole app at {}.", path.display());
            Ok(0)
        }
        CommandKind::Launch { agent, real, args } => launch_agent(core, &agent, &real, &args),
        CommandKind::Uninstall {
            password_stdin,
            targets,
            home,
        } => {
            require_action_password(core, password_stdin, "uninstall")?;
            for target in parse_targets(&targets)? {
                let path = target_path(&target, home.as_deref())?;
                let (removed, backup) = uninstall_json_hook(&path)?;
                if let Some(path) = backup {
                    println!(
                        "Removed {removed} {target} hook(s). backup: {}",
                        path.display()
                    );
                } else {
                    println!("Removed {removed} {target} hook(s).");
                }
            }
            Ok(0)
        }
        CommandKind::Gui => {
            run_gui().map_err(|err| err.to_string())?;
            Ok(0)
        }
    }
}

fn action_list(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_else(|| PASSWORD_ACTIONS.join(","))
        .split(',')
        .filter_map(|part| {
            let clean = part.trim().to_lowercase();
            (!clean.is_empty()).then_some(clean)
        })
        .collect()
}

fn read_stdin_lines() -> Result<Vec<String>, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("Could not read stdin: {err}"))?;
    Ok(input.lines().map(str::to_owned).collect())
}

fn read_new_password(stdin: bool) -> Result<(String, String), String> {
    if stdin {
        let lines = read_stdin_lines()?;
        if lines.len() < 2 {
            return Err("Expected password and confirmation on stdin.".to_owned());
        }
        return Ok((lines[0].clone(), lines[1].clone()));
    }
    Ok((
        rpassword::prompt_password("Password: ").map_err(|_| password_tty_error())?,
        rpassword::prompt_password("Password again: ").map_err(|_| password_tty_error())?,
    ))
}

fn read_current_password(stdin: bool, prompt: &str) -> Result<String, String> {
    if stdin {
        let lines = read_stdin_lines()?;
        return lines
            .first()
            .cloned()
            .ok_or_else(|| "Expected password on stdin.".to_owned());
    }
    rpassword::prompt_password(prompt).map_err(|_| password_tty_error())
}

fn read_password_change(stdin: bool) -> Result<(String, String, String), String> {
    if stdin {
        let lines = read_stdin_lines()?;
        if lines.len() < 3 {
            return Err(
                "Expected current password, new password, and confirmation on stdin.".to_owned(),
            );
        }
        return Ok((lines[0].clone(), lines[1].clone(), lines[2].clone()));
    }
    Ok((
        rpassword::prompt_password("Current password: ").map_err(|_| password_tty_error())?,
        rpassword::prompt_password("Password: ").map_err(|_| password_tty_error())?,
        rpassword::prompt_password("Password again: ").map_err(|_| password_tty_error())?,
    ))
}

fn password_tty_error() -> String {
    "Password input was required but no terminal input was available.".to_owned()
}

fn window_to_cli_value(window: &LockWindow) -> String {
    format!("{}-{} {}", window.start, window.end, window.days.join(","))
}

fn require_action_password(core: &ParoleCore, stdin: bool, action: &str) -> Result<(), String> {
    if !core.is_configured() {
        return Ok(());
    }
    let config = core.load_config()?;
    let required = config
        .password_required_for
        .iter()
        .any(|value| value == action)
        || (action == "uninstall"
            && config
                .password_required_for
                .iter()
                .any(|value| value == "disable"));
    if required {
        let password = read_current_password(stdin, "Current password: ")?;
        core.assert_password(&password)?;
    }
    Ok(())
}

fn parse_targets(raw: &str) -> Result<Vec<String>, String> {
    let targets = raw
        .split(',')
        .filter_map(|part| {
            let clean = part.trim().to_lowercase();
            (!clean.is_empty()).then_some(clean)
        })
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err("At least one target is required.".to_owned());
    }
    for target in &targets {
        if target != "claude" && target != "codex" {
            return Err(format!(
                "Unknown target {target:?}; expected claude or codex."
            ));
        }
    }
    Ok(targets)
}

static INPUT_BLOCKED: AtomicBool = AtomicBool::new(false);

const GUARD_FLAG_CONTROL: u64 = 1 << 18;
const GUARD_FLAG_OPTION: u64 = 1 << 19;
const GUARD_FLAG_COMMAND: u64 = 1 << 20;
const GUARD_KEY_V: i64 = 9;
const GUARD_KEY_J: i64 = 38;
const GUARD_KEY_M: i64 = 46;
const GUARD_KEY_RETURN: i64 = 36;
const GUARD_KEY_ENTER: i64 = 76;

fn should_block_guard_key(key_code: i64, flags: u64) -> bool {
    if key_code == GUARD_KEY_RETURN || key_code == GUARD_KEY_ENTER {
        return true;
    }
    if flags & GUARD_FLAG_COMMAND != 0 {
        return key_code == GUARD_KEY_V;
    }
    if flags & GUARD_FLAG_CONTROL != 0 {
        return key_code == GUARD_KEY_J || key_code == GUARD_KEY_M;
    }
    if flags & GUARD_FLAG_OPTION != 0 {
        return is_text_entry_key_code(key_code);
    }
    is_text_entry_key_code(key_code)
}

fn is_text_entry_key_code(key_code: i64) -> bool {
    matches!(
        key_code,
        0..=50
            | 51
            | 65
            | 67
            | 69
            | 75
            | 78
            | 81
            | 82..=89
            | 91
            | 92
            | 117
    )
}

fn input_guard_status(core: &ParoleCore) -> Result<GuardStatus, String> {
    let decision = if core.is_configured() {
        core.decision()?
    } else {
        Decision {
            allowed: true,
            scheduled_locked: false,
            temporarily_unlocked: false,
            reason: "not configured".to_owned(),
            locked_until: None,
            unlock_expires_at: None,
        }
    };
    let foreground = foreground_target()?;
    let locked = !decision.allowed;
    let blocking_input = locked && foreground.target_focused;
    Ok(GuardStatus {
        locked,
        target_focused: foreground.target_focused,
        blocking_input,
        foreground: foreground.name,
        detail: if blocking_input {
            "curfew active and focused window is a prompt target".to_owned()
        } else if locked {
            "curfew active but focused window is not a prompt target".to_owned()
        } else {
            decision.reason
        },
    })
}

fn run_input_guard(core: ParoleCore, poll_millis: u64) -> Result<i32, String> {
    if poll_millis < 50 {
        return Err("poll-millis must be at least 50.".to_owned());
    }
    println!("Prompt Parole input guard is running.");
    println!("Output remains visible; keyboard input to locked Codex/Claude windows is blocked.");
    let initial_blocking = input_guard_status(&core)
        .map(|status| status.blocking_input)
        .unwrap_or(false);
    INPUT_BLOCKED.store(initial_blocking, Ordering::Relaxed);
    let poll_core = core.clone();
    thread::spawn(move || {
        loop {
            let blocking = input_guard_status(&poll_core)
                .map(|status| status.blocking_input)
                .unwrap_or(false);
            INPUT_BLOCKED.store(blocking, Ordering::Relaxed);
            thread::sleep(StdDuration::from_millis(poll_millis));
        }
    });
    platform_run_input_guard()
}

#[derive(Clone, Debug)]
struct ForegroundTarget {
    name: String,
    target_focused: bool,
}

fn foreground_target() -> Result<ForegroundTarget, String> {
    platform_foreground_target()
}

fn input_guard_running() -> bool {
    !prompt_parole_process_pids("guard").is_empty()
}

const GUARD_AGENT_LABEL: &str = "com.prompt-parole.guard";
const GUARD_WATCHDOG_LABEL: &str = "com.prompt-parole.guard-watchdog";

fn start_guard_agent(core: &ParoleCore) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        if !input_guard_running() {
            start_guard_once(core)?;
        }
        start_guard_watchdog_agent(core)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = core;
        Err("Input Guard agent is currently implemented only for macOS.".to_owned())
    }
}

#[cfg(target_os = "macos")]
fn start_guard_once(core: &ParoleCore) -> Result<(), String> {
    {
        let plist = guard_agent_plist_path()?;
        write_guard_agent_plist(core, &plist)?;
        let domain = launchctl_domain()?;
        let target = launchctl_target(&domain, GUARD_AGENT_LABEL);
        let _ = run_launchctl(&["bootout", &target]);
        match run_launchctl(&["bootstrap", &domain, plist.to_string_lossy().as_ref()])
            .and_then(|_| run_launchctl(&["kickstart", "-k", &target]))
        {
            Ok(()) => {
                thread::sleep(StdDuration::from_millis(900));
                if input_guard_running() {
                    return Ok(());
                }
            }
            Err(err) => {
                eprintln!("prompt-parole: direct launchd guard unavailable: {err}");
                thread::sleep(StdDuration::from_millis(900));
                if input_guard_running() {
                    return Ok(());
                }
            }
        }
        let _ = run_launchctl(&["bootout", &target]);
        start_terminal_guard()
    }
}

#[cfg(not(target_os = "macos"))]
fn start_guard_once(core: &ParoleCore) -> Result<(), String> {
    let _ = core;
    Err("Input Guard agent is currently implemented only for macOS.".to_owned())
}

#[cfg(target_os = "macos")]
fn start_guard_watchdog_agent(core: &ParoleCore) -> Result<(), String> {
    if guard_watchdog_running() {
        return Ok(());
    }
    let plist = guard_watchdog_plist_path()?;
    write_guard_watchdog_plist(core, &plist)?;
    let domain = launchctl_domain()?;
    let target = launchctl_target(&domain, GUARD_WATCHDOG_LABEL);
    let _ = run_launchctl(&["bootout", &target]);
    run_launchctl(&["bootstrap", &domain, plist.to_string_lossy().as_ref()])?;
    run_launchctl(&["kickstart", "-k", &target])?;
    thread::sleep(StdDuration::from_millis(600));
    if guard_watchdog_running() {
        Ok(())
    } else {
        Err("Input guard watchdog did not stay running.".to_owned())
    }
}

fn guard_watchdog_running() -> bool {
    !prompt_parole_process_pids("guard-watchdog").is_empty()
}

fn run_guard_watchdog(core: ParoleCore, interval_seconds: u64) -> Result<i32, String> {
    if interval_seconds == 0 {
        return Err("interval-seconds must be positive.".to_owned());
    }
    println!("Prompt Parole guard watchdog is running.");
    loop {
        let locked = core
            .is_configured()
            .then(|| core.decision().map(|decision| !decision.allowed))
            .transpose()?
            .unwrap_or(false);
        if locked
            && !input_guard_running()
            && let Err(err) = recover_guard_from_watchdog(&core)
        {
            eprintln!("prompt-parole watchdog: could not start input guard: {err}");
        }
        thread::sleep(StdDuration::from_secs(interval_seconds));
    }
}

#[cfg(target_os = "macos")]
fn recover_guard_from_watchdog(core: &ParoleCore) -> Result<(), String> {
    let _ = core;
    start_terminal_guard()
}

#[cfg(not(target_os = "macos"))]
fn recover_guard_from_watchdog(core: &ParoleCore) -> Result<(), String> {
    start_guard_once(core)
}

#[cfg(target_os = "macos")]
fn start_terminal_guard() -> Result<(), String> {
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("prompt-parole"));
    let command = format!("{} guard", shell_quote(&exe.to_string_lossy()));
    let script = format!(
        "tell application \"Terminal\" to do script \"{}\"",
        applescript_string_escape(&command)
    );
    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|err| format!("Could not start Terminal input guard: {err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    thread::sleep(StdDuration::from_millis(900));
    if input_guard_running() {
        Ok(())
    } else {
        Err("Input guard did not stay running. Check macOS Accessibility/Input Monitoring permission for Terminal or prompt-parole.".to_owned())
    }
}

#[cfg(target_os = "macos")]
fn applescript_string_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn stop_guard_agent(core: &ParoleCore) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let _ = core;
        let domain = launchctl_domain()?;
        let guard_target = launchctl_target(&domain, GUARD_AGENT_LABEL);
        let watchdog_target = launchctl_target(&domain, GUARD_WATCHDOG_LABEL);
        let result = stop_launchctl_target(&guard_target)
            .and_then(|_| stop_launchctl_target(&watchdog_target));
        stop_guard_processes();
        stop_guard_watchdog_processes();
        result
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = core;
        Err("Input Guard agent is currently implemented only for macOS.".to_owned())
    }
}

fn stop_guard_processes() {
    for pid in prompt_parole_process_pids("guard") {
        let _ = Command::new("kill").arg(pid.to_string()).status();
    }
}

fn stop_guard_watchdog_processes() {
    for pid in prompt_parole_process_pids("guard-watchdog") {
        let _ = Command::new("kill").arg(pid.to_string()).status();
    }
}

fn prompt_parole_process_pids(command_arg: &str) -> Vec<u32> {
    let Ok(output) = Command::new("ps").args(["-axo", "pid=,args="]).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let self_pid = std::process::id().to_string();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| parse_prompt_parole_process_line(line, &self_pid, command_arg))
        .collect()
}

fn parse_prompt_parole_process_line(line: &str, self_pid: &str, command_arg: &str) -> Option<u32> {
    let mut parts = line.trim_start().splitn(2, char::is_whitespace);
    let pid = parts.next()?;
    if pid == self_pid {
        return None;
    }
    let args = parts.next().unwrap_or("");
    let mut arg_parts = args.split_whitespace();
    let exe = arg_parts.next()?;
    let exe_name = Path::new(exe).file_name()?.to_str()?;
    if exe_name != "prompt-parole" {
        return None;
    }
    arg_parts
        .any(|arg| arg == command_arg)
        .then(|| pid.parse().ok())?
}

fn guard_agent_plist_path() -> Result<PathBuf, String> {
    launch_agent_plist_path(GUARD_AGENT_LABEL)
}

fn guard_watchdog_plist_path() -> Result<PathBuf, String> {
    launch_agent_plist_path(GUARD_WATCHDOG_LABEL)
}

fn launch_agent_plist_path(label: &str) -> Result<PathBuf, String> {
    dirs::home_dir()
        .map(|home| {
            home.join("Library")
                .join("LaunchAgents")
                .join(format!("{label}.plist"))
        })
        .ok_or_else(|| "Could not find home directory.".to_owned())
}

fn write_guard_agent_plist(core: &ParoleCore, path: &Path) -> Result<(), String> {
    write_prompt_parole_agent_plist(core, path, GUARD_AGENT_LABEL, &["guard"], "guard")
}

fn write_guard_watchdog_plist(core: &ParoleCore, path: &Path) -> Result<(), String> {
    write_prompt_parole_agent_plist(
        core,
        path,
        GUARD_WATCHDOG_LABEL,
        &["guard-watchdog", "--interval-seconds", "2"],
        "guard-watchdog",
    )
}

fn write_prompt_parole_agent_plist(
    core: &ParoleCore,
    path: &Path,
    label: &str,
    args: &[&str],
    log_stem: &str,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory.", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("Could not create {}: {err}", parent.display()))?;
    ensure_private_dir(&core.app_dir)?;
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("prompt-parole"));
    let log = core.app_dir.join(format!("{log_stem}.log"));
    let err = core.app_dir.join(format!("{log_stem}.err.log"));
    let plist = launch_agent_plist(label, &exe, args, &log, &err);
    fs::write(path, plist).map_err(|err| format!("Could not write {}: {err}", path.display()))?;
    Ok(())
}

fn launch_agent_plist(
    label: &str,
    exe: &Path,
    args: &[&str],
    stdout: &Path,
    stderr: &Path,
) -> String {
    let arg_xml = args
        .iter()
        .map(|arg| format!("    <string>{}</string>", xml_escape(arg)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
{arg_xml}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
</dict>
</plist>
"#,
        label = xml_escape(label),
        exe = xml_escape(&exe.to_string_lossy()),
        arg_xml = arg_xml,
        stdout = xml_escape(&stdout.to_string_lossy()),
        stderr = xml_escape(&stderr.to_string_lossy())
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn launchctl_domain() -> Result<String, String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|err| format!("Could not determine user id: {err}"))?;
    if !output.status.success() {
        return Err("Could not determine user id.".to_owned());
    }
    Ok(format!(
        "gui/{}",
        String::from_utf8_lossy(&output.stdout).trim()
    ))
}

fn launchctl_target(domain: &str, label: &str) -> String {
    format!("{domain}/{label}")
}

fn stop_launchctl_target(target: &str) -> Result<(), String> {
    run_launchctl(&["bootout", target]).or_else(|err| {
        if err.contains("No such process")
            || err.contains("Could not find service")
            || err.contains("service not found")
        {
            Ok(())
        } else {
            Err(err)
        }
    })
}

fn run_launchctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|err| format!("Could not run launchctl: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Err(if stderr.is_empty() {
        format!("launchctl {:?} failed: {stdout}", args)
    } else {
        format!("launchctl {:?} failed: {stderr}", args)
    })
}

#[cfg(target_os = "macos")]
fn platform_foreground_target() -> Result<ForegroundTarget, String> {
    let Some(window) = macos_front_window::frontmost_window() else {
        return Ok(ForegroundTarget {
            name: "no foreground window".to_owned(),
            target_focused: false,
        });
    };
    let name = if window.title.is_empty() {
        window.owner.clone()
    } else {
        format!("{}: {}", window.owner, window.title)
    };
    Ok(ForegroundTarget {
        target_focused: window_is_agent_target(&window.owner, &window.title),
        name,
    })
}

#[cfg(not(target_os = "macos"))]
fn platform_foreground_target() -> Result<ForegroundTarget, String> {
    Ok(ForegroundTarget {
        name: "unsupported platform".to_owned(),
        target_focused: false,
    })
}

#[cfg(target_os = "macos")]
fn platform_run_input_guard() -> Result<i32, String> {
    macos_event_tap::run()
}

#[cfg(not(target_os = "macos"))]
fn platform_run_input_guard() -> Result<i32, String> {
    Err("Input Guard is currently implemented only for macOS.".to_owned())
}

fn window_is_agent_target(owner: &str, title: &str) -> bool {
    let owner = owner.to_ascii_lowercase();
    let title = title.to_ascii_lowercase();
    if owner.contains("codex") || owner.contains("claude") {
        return true;
    }
    owner == "terminal" && (title.contains("codex") || title.contains("claude"))
}

#[cfg(target_os = "macos")]
mod macos_front_window {
    use std::ffi::{c_char, c_void};

    type CfArrayRef = *const c_void;
    type CfDictionaryRef = *const c_void;
    type CfStringRef = *const c_void;
    type CfNumberRef = *const c_void;
    type CfIndex = isize;

    const K_CG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY: u32 = 1;
    const K_CG_WINDOW_LIST_EXCLUDE_DESKTOP_ELEMENTS: u32 = 16;
    const K_CF_NUMBER_INT_TYPE: u32 = 9;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[derive(Clone, Debug)]
    pub struct WindowInfo {
        pub owner: String,
        pub title: String,
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        static kCGWindowOwnerName: CfStringRef;
        static kCGWindowName: CfStringRef;
        static kCGWindowLayer: CfStringRef;
        fn CGWindowListCopyWindowInfo(option: u32, relative_to_window: u32) -> CfArrayRef;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFArrayGetCount(array: CfArrayRef) -> CfIndex;
        fn CFArrayGetValueAtIndex(array: CfArrayRef, index: CfIndex) -> *const c_void;
        fn CFDictionaryGetValue(dict: CfDictionaryRef, key: *const c_void) -> *const c_void;
        fn CFNumberGetValue(number: CfNumberRef, number_type: u32, value_ptr: *mut c_void) -> bool;
        fn CFStringGetCString(
            string: CfStringRef,
            buffer: *mut c_char,
            buffer_size: CfIndex,
            encoding: u32,
        ) -> bool;
        fn CFRelease(value: *const c_void);
    }

    pub fn frontmost_window() -> Option<WindowInfo> {
        unsafe {
            let list = CGWindowListCopyWindowInfo(
                K_CG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY | K_CG_WINDOW_LIST_EXCLUDE_DESKTOP_ELEMENTS,
                0,
            );
            if list.is_null() {
                return None;
            }
            let count = CFArrayGetCount(list);
            let mut result = None;
            for index in 0..count {
                let dict = CFArrayGetValueAtIndex(list, index) as CfDictionaryRef;
                if dict.is_null() || window_layer(dict) != Some(0) {
                    continue;
                }
                let owner = dictionary_string(dict, kCGWindowOwnerName).unwrap_or_default();
                if owner.is_empty()
                    || matches!(
                        owner.as_str(),
                        "Window Server"
                            | "Dock"
                            | "Control Center"
                            | "Notification Center"
                            | "SystemUIServer"
                    )
                {
                    continue;
                }
                let title = dictionary_string(dict, kCGWindowName).unwrap_or_default();
                result = Some(WindowInfo { owner, title });
                break;
            }
            CFRelease(list);
            result
        }
    }

    unsafe fn window_layer(dict: CfDictionaryRef) -> Option<i32> {
        let value = unsafe { CFDictionaryGetValue(dict, kCGWindowLayer) as CfNumberRef };
        if value.is_null() {
            return None;
        }
        let mut layer = 0_i32;
        let ok = unsafe {
            CFNumberGetValue(
                value,
                K_CF_NUMBER_INT_TYPE,
                (&mut layer as *mut i32).cast::<c_void>(),
            )
        };
        ok.then_some(layer)
    }

    unsafe fn dictionary_string(dict: CfDictionaryRef, key: CfStringRef) -> Option<String> {
        let value = unsafe { CFDictionaryGetValue(dict, key) as CfStringRef };
        if value.is_null() {
            return None;
        }
        unsafe { cf_string(value) }
    }

    unsafe fn cf_string(value: CfStringRef) -> Option<String> {
        let mut buffer = [0_i8; 1024];
        let ok = unsafe {
            CFStringGetCString(
                value,
                buffer.as_mut_ptr(),
                buffer.len() as CfIndex,
                K_CF_STRING_ENCODING_UTF8,
            )
        };
        if !ok {
            return None;
        }
        let len = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        let bytes = buffer[..len]
            .iter()
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>();
        String::from_utf8(bytes).ok()
    }
}

#[cfg(target_os = "macos")]
mod macos_event_tap {
    use super::{INPUT_BLOCKED, should_block_guard_key};
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    type CgEventTapProxy = *mut c_void;
    type CgEventRef = *mut c_void;
    type CfMachPortRef = *mut c_void;
    type CfRunLoopSourceRef = *mut c_void;
    type CfRunLoopRef = *mut c_void;
    type CfAllocatorRef = *const c_void;
    type CfStringRef = *const c_void;
    type CgEventTapCallback =
        extern "C" fn(CgEventTapProxy, u32, CgEventRef, *mut c_void) -> CgEventRef;

    const K_CG_SESSION_EVENT_TAP: u32 = 1;
    const K_CG_HEAD_INSERT_EVENT_TAP: u32 = 0;
    const K_CG_EVENT_TAP_OPTION_DEFAULT: u32 = 0;
    const K_CG_EVENT_KEY_DOWN: u32 = 10;
    const K_CG_KEYBOARD_EVENT_KEYCODE: u32 = 9;

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn CGEventTapCreate(
            tap: u32,
            place: u32,
            options: u32,
            events_of_interest: u64,
            callback: CgEventTapCallback,
            user_info: *mut c_void,
        ) -> CfMachPortRef;
        fn CGEventTapEnable(tap: CfMachPortRef, enable: bool);
        fn CGEventGetIntegerValueField(event: CgEventRef, field: u32) -> i64;
        fn CGEventGetFlags(event: CgEventRef) -> u64;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFRunLoopCommonModes: CfStringRef;
        static kCFRunLoopDefaultMode: CfStringRef;
        fn CFMachPortCreateRunLoopSource(
            allocator: CfAllocatorRef,
            port: CfMachPortRef,
            order: isize,
        ) -> CfRunLoopSourceRef;
        fn CFRunLoopGetCurrent() -> CfRunLoopRef;
        fn CFRunLoopAddSource(rl: CfRunLoopRef, source: CfRunLoopSourceRef, mode: CfStringRef);
        fn CFRunLoopRunInMode(
            mode: CfStringRef,
            seconds: f64,
            return_after_source_handled: bool,
        ) -> i32;
    }

    extern "C" fn event_callback(
        _proxy: CgEventTapProxy,
        event_type: u32,
        event: CgEventRef,
        _user_info: *mut c_void,
    ) -> CgEventRef {
        if event_type == K_CG_EVENT_KEY_DOWN && INPUT_BLOCKED.load(Ordering::Relaxed) {
            let key_code =
                unsafe { CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE) };
            let flags = unsafe { CGEventGetFlags(event) };
            if should_block_guard_key(key_code, flags) {
                return ptr::null_mut();
            }
        }
        event
    }

    pub fn run() -> Result<i32, String> {
        let mask = 1_u64 << K_CG_EVENT_KEY_DOWN;
        unsafe {
            let tap = CGEventTapCreate(
                K_CG_SESSION_EVENT_TAP,
                K_CG_HEAD_INSERT_EVENT_TAP,
                K_CG_EVENT_TAP_OPTION_DEFAULT,
                mask,
                event_callback,
                ptr::null_mut(),
            );
            if tap.is_null() {
                return Err(
                    "Could not create macOS keyboard event tap. Grant Accessibility/Input Monitoring permission to prompt-parole, then start Input Guard again."
                        .to_owned(),
                );
            }
            let source = CFMachPortCreateRunLoopSource(ptr::null(), tap, 0);
            if source.is_null() {
                return Err("Could not create macOS event-tap run loop source.".to_owned());
            }
            let run_loop = CFRunLoopGetCurrent();
            CFRunLoopAddSource(run_loop, source, kCFRunLoopDefaultMode);
            CFRunLoopAddSource(run_loop, source, kCFRunLoopCommonModes);
            CGEventTapEnable(tap, true);
            loop {
                CGEventTapEnable(tap, true);
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 3600.0, false);
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

fn protection_status() -> ProtectionStatus {
    ProtectionStatus {
        codex_hook: hook_installed("codex"),
        claude_hook: hook_installed("claude"),
        codex_launcher: launcher_installed("codex"),
        claude_launcher: launcher_installed("claude"),
        codex_path_uses_launcher: command_uses_launcher("codex"),
        claude_path_uses_launcher: command_uses_launcher("claude"),
        input_guard_running: input_guard_running(),
        mac_app_installed: macos_app_bundle_installed(),
    }
}

fn hook_installed(target: &str) -> bool {
    let Ok(path) = target_path(target, None) else {
        return false;
    };
    let agent = target_agent(target);
    prompt_parole_hook_installed(&path, &agent)
}

fn prompt_parole_hook_installed(path: &Path, agent: &str) -> bool {
    let Ok(data) = load_json_object(path) else {
        return false;
    };
    let Some(groups) = data
        .get("hooks")
        .and_then(|value| value.get("UserPromptSubmit"))
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    groups.iter().any(|group| {
        group
            .get("hooks")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("command")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|command| is_prompt_parole_hook_command(command, agent))
                })
            })
    })
}

fn is_prompt_parole_hook_command(command: &str, agent: &str) -> bool {
    let has_marker =
        command.contains("PROMPT_PAROLE_HOOK=1") || command.contains("prompt-parole hook --agent");
    has_marker
        && (command.contains(&format!("--agent {agent}"))
            || (agent == "claude-code" && command.contains("--agent claude")))
}

fn launcher_installed(target: &str) -> bool {
    launcher_bin_dir(None).is_ok_and(|dir| is_prompt_parole_launcher(&dir.join(target)))
}

fn command_uses_launcher(target: &str) -> bool {
    find_on_path(target).is_some_and(|path| is_prompt_parole_launcher(&path))
}

fn find_on_path(target: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    for dir in env::split_paths(&paths) {
        let candidate = dir.join(target);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

struct LauncherInstallReport {
    wrapper: PathBuf,
    backup: Option<PathBuf>,
}

fn install_launcher(target: &str, bin_dir: Option<&Path>) -> Result<LauncherInstallReport, String> {
    let dir = launcher_bin_dir(bin_dir)?;
    fs::create_dir_all(&dir).map_err(|err| format!("Could not create {}: {err}", dir.display()))?;
    let wrapper = dir.join(target);
    let real = locate_real_agent_binary(target, &wrapper)?;
    let backup = if wrapper.exists() && !is_prompt_parole_launcher(&wrapper) {
        let backup = wrapper.with_file_name(format!(
            "{}.prompt-parole.backup.{}",
            target,
            Utc::now().format("%Y%m%d%H%M%S")
        ));
        fs::rename(&wrapper, &backup).map_err(|err| {
            format!(
                "Could not back up {} to {}: {err}",
                wrapper.display(),
                backup.display()
            )
        })?;
        Some(backup)
    } else {
        None
    };
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("prompt-parole"));
    write_launcher_script(&wrapper, &exe, target, &real)?;
    Ok(LauncherInstallReport { wrapper, backup })
}

fn uninstall_launcher(target: &str, bin_dir: Option<&Path>) -> Result<Option<PathBuf>, String> {
    let dir = launcher_bin_dir(bin_dir)?;
    let wrapper = dir.join(target);
    if wrapper.exists() {
        if !is_prompt_parole_launcher(&wrapper) {
            return Err(format!(
                "{} is not a Prompt Parole launcher; refusing to remove it.",
                wrapper.display()
            ));
        }
        fs::remove_file(&wrapper)
            .map_err(|err| format!("Could not remove {}: {err}", wrapper.display()))?;
    }
    if let Some(backup) = latest_launcher_backup(&dir, target)? {
        fs::rename(&backup, &wrapper).map_err(|err| {
            format!(
                "Could not restore {} to {}: {err}",
                backup.display(),
                wrapper.display()
            )
        })?;
        return Ok(Some(wrapper));
    }
    Ok(None)
}

fn launcher_bin_dir(bin_dir: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = bin_dir {
        return Ok(path.to_path_buf());
    }
    dirs::home_dir()
        .map(|home| home.join(".local").join("bin"))
        .ok_or_else(|| "Could not find home directory.".to_owned())
}

fn locate_real_agent_binary(target: &str, wrapper: &Path) -> Result<PathBuf, String> {
    if wrapper.exists()
        && !is_prompt_parole_launcher(wrapper)
        && let Ok(path) = fs::canonicalize(wrapper)
    {
        return Ok(path);
    }

    let output = Command::new("which")
        .args(["-a", target])
        .output()
        .map_err(|err| format!("Could not find {target}: {err}"))?;
    if output.status.success()
        && let Some(path) =
            first_real_agent_candidate(String::from_utf8_lossy(&output.stdout).lines(), wrapper)
    {
        return fs::canonicalize(&path)
            .map_err(|err| format!("Could not resolve {}: {err}", path.display()));
    }

    let known = if target == "codex" {
        vec![
            PathBuf::from("/opt/homebrew/bin/codex"),
            PathBuf::from("/usr/local/bin/codex"),
            PathBuf::from("/usr/bin/codex"),
        ]
    } else {
        vec![
            PathBuf::from("/opt/homebrew/bin/claude"),
            PathBuf::from("/usr/local/bin/claude"),
            PathBuf::from("/usr/bin/claude"),
        ]
    };
    for path in known {
        if path.exists() && path != wrapper {
            return fs::canonicalize(&path)
                .map_err(|err| format!("Could not resolve {}: {err}", path.display()));
        }
    }

    Err(format!("Could not find the real {target} binary."))
}

fn first_real_agent_candidate<'a>(
    candidates: impl IntoIterator<Item = &'a str>,
    wrapper: &Path,
) -> Option<PathBuf> {
    candidates.into_iter().find_map(|line| {
        let clean = line.trim();
        if clean.is_empty() {
            return None;
        }
        let path = PathBuf::from(clean);
        if path == wrapper || is_prompt_parole_launcher(&path) {
            return None;
        }
        path.exists().then_some(path)
    })
}

fn write_launcher_script(
    wrapper: &Path,
    prompt_parole_exe: &Path,
    target: &str,
    real: &Path,
) -> Result<(), String> {
    let script = format!(
        "#!/bin/sh\n# PROMPT_PAROLE_LAUNCHER=1\nexec {} launch --agent {} --real {} -- \"$@\"\n",
        shell_quote(&prompt_parole_exe.to_string_lossy()),
        shell_quote(target),
        shell_quote(&real.to_string_lossy())
    );
    fs::write(wrapper, script)
        .map_err(|err| format!("Could not write {}: {err}", wrapper.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(wrapper, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("Could not make {} executable: {err}", wrapper.display()))?;
    }
    Ok(())
}

fn is_prompt_parole_launcher(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|value| value.contains("PROMPT_PAROLE_LAUNCHER=1"))
}

fn latest_launcher_backup(dir: &Path, target: &str) -> Result<Option<PathBuf>, String> {
    if !dir.exists() {
        return Ok(None);
    }
    let prefix = format!("{target}.prompt-parole.backup.");
    let mut backups = Vec::new();
    for entry in
        fs::read_dir(dir).map_err(|err| format!("Could not read {}: {err}", dir.display()))?
    {
        let entry = entry.map_err(|err| format!("Could not read launcher backup: {err}"))?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(&prefix) {
            backups.push(entry.path());
        }
    }
    backups.sort();
    Ok(backups.pop())
}

#[cfg(target_os = "macos")]
fn install_macos_app_bundle(app_dir: Option<&Path>) -> Result<PathBuf, String> {
    let root = match app_dir {
        Some(path) => path.to_path_buf(),
        None => dirs::home_dir()
            .map(|home| home.join("Applications"))
            .ok_or_else(|| "Could not find home directory.".to_owned())?,
    };
    fs::create_dir_all(&root)
        .map_err(|err| format!("Could not create {}: {err}", root.display()))?;

    let app = root.join("Prompt Parole.app");
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    let resources = contents.join("Resources");
    fs::create_dir_all(&macos)
        .map_err(|err| format!("Could not create {}: {err}", macos.display()))?;
    fs::create_dir_all(&resources)
        .map_err(|err| format!("Could not create {}: {err}", resources.display()))?;

    let exe =
        env::current_exe().map_err(|err| format!("Could not locate current executable: {err}"))?;
    let bundled_exe = macos.join("prompt-parole");
    let same_file = fs::canonicalize(&exe).ok() == fs::canonicalize(&bundled_exe).ok();
    if !same_file {
        fs::copy(&exe, &bundled_exe).map_err(|err| {
            format!(
                "Could not copy {} to {}: {err}",
                exe.display(),
                bundled_exe.display()
            )
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bundled_exe, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("Could not make {} executable: {err}", bundled_exe.display()))?;
    }

    fs::write(contents.join("Info.plist"), macos_app_info_plist())
        .map_err(|err| format!("Could not write Info.plist: {err}"))?;
    fs::write(contents.join("PkgInfo"), "APPL????\n")
        .map_err(|err| format!("Could not write PkgInfo: {err}"))?;
    Ok(app)
}

#[cfg(not(target_os = "macos"))]
fn install_macos_app_bundle(app_dir: Option<&Path>) -> Result<PathBuf, String> {
    let _ = app_dir;
    Err("macOS app bundle installation is only available on macOS.".to_owned())
}

fn macos_app_info_plist() -> String {
    let name = "Prompt Parole";
    let executable = "prompt-parole";
    let identifier = "com.prompt-parole.desktop";
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>{name}</string>
  <key>CFBundleExecutable</key>
  <string>{executable}</string>
  <key>CFBundleIdentifier</key>
  <string>{identifier}</string>
  <key>CFBundleName</key>
  <string>{name}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>{version}</string>
  <key>CFBundleVersion</key>
  <string>{version}</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.productivity</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
"#,
        name = xml_escape(name),
        executable = xml_escape(executable),
        identifier = xml_escape(identifier),
        version = xml_escape(env!("CARGO_PKG_VERSION")),
    )
}

#[cfg(target_os = "macos")]
fn macos_app_bundle_installed() -> bool {
    dirs::home_dir()
        .map(|home| home.join("Applications").join("Prompt Parole.app"))
        .is_some_and(|app| {
            let info = app.join("Contents").join("Info.plist");
            let exe = app.join("Contents").join("MacOS").join("prompt-parole");
            info.is_file()
                && exe.is_file()
                && fs::read_to_string(info).is_ok_and(|value| {
                    value.contains("<string>Prompt Parole</string>")
                        && value.contains("<string>APPL</string>")
                })
        })
}

#[cfg(not(target_os = "macos"))]
fn macos_app_bundle_installed() -> bool {
    false
}

fn launch_agent(
    core: &ParoleCore,
    agent: &str,
    real: &Path,
    args: &[String],
) -> Result<i32, String> {
    if agent != "codex" && agent != "claude" {
        return Err(format!("Unsupported launcher agent {agent:?}."));
    }
    if core.is_configured() {
        let decision = core.decision()?;
        if !decision.allowed {
            let until = decision
                .locked_until
                .map(|value| value.format("%Y-%m-%d %H:%M %Z").to_string())
                .unwrap_or_else(|| "the scheduled unlock time".to_owned());
            eprintln!("Prompt Parole: curfew is active until {until}.");
            return Ok(1);
        }
    }
    let mut command = Command::new(real);
    if agent == "codex"
        && !args
            .iter()
            .any(|arg| arg == "--dangerously-bypass-hook-trust")
    {
        command.arg("--dangerously-bypass-hook-trust");
    }
    let status = command
        .args(args)
        .status()
        .map_err(|err| format!("Could not launch {}: {err}", real.display()))?;
    Ok(status.code().unwrap_or(1))
}

fn target_agent(target: &str) -> String {
    if target == "claude" {
        "claude-code".to_owned()
    } else {
        "codex".to_owned()
    }
}

fn target_path(target: &str, home: Option<&Path>) -> Result<PathBuf, String> {
    let root = home
        .map(Path::to_path_buf)
        .or_else(dirs::home_dir)
        .ok_or_else(|| "Could not find home directory.".to_owned())?;
    Ok(if target == "claude" {
        root.join(".claude").join("settings.json")
    } else {
        root.join(".codex").join("hooks.json")
    })
}

fn default_hook_command(agent: &str) -> String {
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("prompt-parole"));
    format!(
        "PROMPT_PAROLE_HOOK=1 {} hook --agent {}",
        shell_quote(&exe.to_string_lossy()),
        shell_quote(agent),
    )
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "/._-".contains(ch))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn install_json_hook(
    path: &Path,
    command: &str,
    status_message: &str,
) -> Result<Option<PathBuf>, String> {
    let mut data = load_json_object(path)?;
    remove_prompt_parole_hooks(&mut data)?;
    let hooks = data
        .as_object_mut()
        .ok_or_else(|| "Hook config must be a JSON object.".to_owned())?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "Existing hooks field must be an object.".to_owned())?;
    let groups = hooks_obj
        .entry("UserPromptSubmit")
        .or_insert_with(|| serde_json::json!([]));
    let groups_arr = groups
        .as_array_mut()
        .ok_or_else(|| "Existing hooks.UserPromptSubmit field must be a list.".to_owned())?;
    groups_arr.push(serde_json::json!({
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": 5,
            "statusMessage": status_message,
        }]
    }));
    let backup = backup_file(path)?;
    write_json_atomic(path, &data)?;
    Ok(backup)
}

fn uninstall_json_hook(path: &Path) -> Result<(usize, Option<PathBuf>), String> {
    let mut data = load_json_object(path)?;
    let removed = remove_prompt_parole_hooks(&mut data)?;
    if removed == 0 {
        return Ok((0, None));
    }
    let backup = backup_file(path)?;
    write_json_atomic(path, &data)?;
    Ok((removed, backup))
}

fn load_json_object(path: &Path) -> Result<serde_json::Value, String> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("Could not read {}: {err}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| format!("{} is not valid JSON: {err}", path.display()))?;
    if !value.is_object() {
        return Err(format!("{} must contain a JSON object.", path.display()));
    }
    Ok(value)
}

fn remove_prompt_parole_hooks(data: &mut serde_json::Value) -> Result<usize, String> {
    let Some(hooks) = data.get_mut("hooks") else {
        return Ok(0);
    };
    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| "Existing hooks field must be an object.".to_owned())?;
    let Some(groups) = hooks_obj.get_mut("UserPromptSubmit") else {
        return Ok(0);
    };
    let groups_arr = groups
        .as_array_mut()
        .ok_or_else(|| "Existing hooks.UserPromptSubmit field must be a list.".to_owned())?;
    let mut removed = 0;
    let mut kept_groups = Vec::new();
    for group in groups_arr.drain(..) {
        let Some(group_obj) = group.as_object() else {
            kept_groups.push(group);
            continue;
        };
        let Some(hooks_value) = group_obj.get("hooks") else {
            kept_groups.push(group);
            continue;
        };
        let Some(hook_arr) = hooks_value.as_array() else {
            kept_groups.push(group);
            continue;
        };
        let kept_hooks = hook_arr
            .iter()
            .filter_map(|hook| {
                let command = hook
                    .get("command")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let is_ours = command.contains("PROMPT_PAROLE_HOOK=1")
                    || command.contains("prompt-parole hook --agent")
                    || command.contains("prompt_parole hook --agent");
                if is_ours {
                    removed += 1;
                    None
                } else {
                    Some(hook.clone())
                }
            })
            .collect::<Vec<_>>();
        if !kept_hooks.is_empty() {
            let mut next = group.clone();
            next["hooks"] = serde_json::Value::Array(kept_hooks);
            kept_groups.push(next);
        }
    }
    *groups_arr = kept_groups;
    if groups_arr.is_empty() {
        hooks_obj.remove("UserPromptSubmit");
    }
    if hooks_obj.is_empty() {
        data.as_object_mut()
            .expect("object checked")
            .remove("hooks");
    }
    Ok(removed)
}

fn backup_file(path: &Path) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let stamp = Utc::now().format("%Y%m%d%H%M%S");
    let backup = path.with_file_name(format!(
        "{}.bak.{stamp}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("config")
    ));
    fs::copy(path, &backup)
        .map_err(|err| format!("Could not create backup {}: {err}", backup.display()))?;
    Ok(Some(backup))
}

fn run_gui() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Prompt Parole")
            .with_inner_size([760.0, 460.0])
            .with_min_inner_size([620.0, 400.0]),
        centered: true,
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "Prompt Parole",
        options,
        Box::new(|_| Ok(Box::new(PromptParoleApp::new()))),
    )
}

fn main() {
    let cli = Cli::parse();
    if let Some(command) = cli.command {
        let core = ParoleCore { app_dir: app_dir() };
        match run_cli(command, &core) {
            Ok(code) => std::process::exit(code),
            Err(err) => {
                eprintln!("prompt-parole: {err}");
                std::process::exit(2);
            }
        }
    }
    if let Err(err) = run_gui() {
        eprintln!("prompt-parole: {err}");
        std::process::exit(2);
    }
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
    fn short_password_is_valid_and_blank_password_is_rejected() {
        let secret = hash_password("ok").unwrap();
        assert!(verify_password("ok", &secret).unwrap());
        assert!(!verify_password("wrong", &secret).unwrap());
        assert!(hash_password("   ").unwrap_err().contains("empty"));
    }

    #[test]
    fn parse_window_defaults_to_every_day() {
        let window = parse_window("19:00-05:00").unwrap();
        assert_eq!(window.start, "19:00");
        assert_eq!(window.end, "05:00");
        assert_eq!(window.days, DAYS);
    }

    #[test]
    fn schedule_cross_midnight_uses_the_start_day() {
        let config = normalize_config(Config {
            version: 1,
            timezone: "local".to_owned(),
            unlock_duration_minutes: 30,
            password_required_for: vec!["unlock".to_owned(), "passwd".to_owned()],
            lock_windows: vec![LockWindow {
                start: "19:00".to_owned(),
                end: "05:00".to_owned(),
                days: vec!["sat".to_owned()],
            }],
            log_prompt_text: false,
        })
        .unwrap();
        let now = DateTime::parse_from_rfc3339("2026-06-21T03:00:00+08:00").unwrap();
        let until = scheduled_lock_until(&config, now).unwrap().unwrap();
        assert_eq!(until.to_rfc3339(), "2026-06-21T05:00:00+08:00");
    }

    #[test]
    fn password_actions_keep_hard_required_actions_but_do_not_force_install() {
        let config = normalize_config(Config {
            version: 1,
            timezone: "local".to_owned(),
            unlock_duration_minutes: 30,
            password_required_for: vec!["disable".to_owned()],
            lock_windows: default_config().lock_windows,
            log_prompt_text: false,
        })
        .unwrap();
        assert!(
            config
                .password_required_for
                .contains(&"configure".to_owned())
        );
        assert!(config.password_required_for.contains(&"disable".to_owned()));
        assert!(config.password_required_for.contains(&"passwd".to_owned()));
        assert!(config.password_required_for.contains(&"unlock".to_owned()));
        assert!(!config.password_required_for.contains(&"install".to_owned()));
    }

    #[test]
    fn hook_payload_blocks_for_locked_config() {
        let dir = tempfile::tempdir().unwrap();
        let core = ParoleCore {
            app_dir: dir.path().to_path_buf(),
        };
        core.setup(
            "ok",
            vec![
                "00:00-23:59 mon,tue,wed,thu,fri,sat,sun".to_owned(),
                "23:59-00:00 mon,tue,wed,thu,fri,sat,sun".to_owned(),
            ],
            "local".to_owned(),
            30,
            PASSWORD_ACTIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        )
        .unwrap();
        let codex = core.hook_payload("codex").unwrap().unwrap();
        assert_eq!(codex["decision"], "block");
        assert!(codex["reason"].as_str().unwrap().contains("curfew"));
        let claude = core.hook_payload("claude-code").unwrap().unwrap();
        assert_eq!(claude["suppressOriginalPrompt"], true);
    }

    #[test]
    fn claude_hook_accepts_legacy_agent_alias() {
        let dir = tempfile::tempdir().unwrap();
        let core = ParoleCore {
            app_dir: dir.path().to_path_buf(),
        };
        core.setup(
            "ok",
            vec!["00:00-23:59 mon,tue,wed,thu,fri,sat,sun".to_owned()],
            "local".to_owned(),
            30,
            PASSWORD_ACTIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        )
        .unwrap();

        let payload = core.hook_payload("claude").unwrap().unwrap();

        assert_eq!(payload["decision"], "block");
        assert_eq!(payload["suppressOriginalPrompt"], true);
    }

    #[test]
    fn install_and_uninstall_hook_preserve_other_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        write_json_atomic(
            &path,
            &serde_json::json!({
                "hooks": {
                    "UserPromptSubmit": [{
                        "hooks": [{
                            "type": "command",
                            "command": "echo keep-me",
                            "timeout": 1
                        }]
                    }]
                }
            }),
        )
        .unwrap();
        install_json_hook(
            &path,
            "PROMPT_PAROLE_HOOK=1 /tmp/prompt-parole hook --agent codex",
            "Checking Prompt Parole curfew",
        )
        .unwrap();
        let installed = load_json_object(&path).unwrap();
        let groups = installed["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(groups.len(), 2);

        let (removed, _) = uninstall_json_hook(&path).unwrap();
        assert_eq!(removed, 1);
        let uninstalled = load_json_object(&path).unwrap();
        let groups = uninstalled["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0]["hooks"][0]["command"].as_str().unwrap(),
            "echo keep-me"
        );
    }

    #[test]
    fn prompt_parole_hook_status_detects_agent_specific_hook() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        write_json_atomic(
            &path,
            &serde_json::json!({
                "hooks": {
                    "UserPromptSubmit": [{
                        "hooks": [{
                            "type": "command",
                            "command": "PROMPT_PAROLE_HOOK=1 /tmp/prompt-parole hook --agent codex",
                            "timeout": 5
                        }]
                    }]
                }
            }),
        )
        .unwrap();

        assert!(prompt_parole_hook_installed(&path, "codex"));
        assert!(!prompt_parole_hook_installed(&path, "claude-code"));
    }

    #[test]
    fn hook_status_accepts_legacy_claude_agent_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        write_json_atomic(
            &path,
            &serde_json::json!({
                "hooks": {
                    "UserPromptSubmit": [{
                        "hooks": [{
                            "type": "command",
                            "command": "PROMPT_PAROLE_HOOK=1 /tmp/prompt-parole hook --agent claude",
                            "timeout": 5
                        }]
                    }]
                }
            }),
        )
        .unwrap();

        assert!(prompt_parole_hook_installed(&path, "claude-code"));
    }

    #[test]
    fn launcher_script_is_marked_as_prompt_parole_launcher() {
        let dir = tempfile::tempdir().unwrap();
        let wrapper = dir.path().join("codex");
        write_launcher_script(
            &wrapper,
            Path::new("/tmp/prompt-parole"),
            "codex",
            Path::new("/opt/homebrew/bin/codex"),
        )
        .unwrap();

        assert!(is_prompt_parole_launcher(&wrapper));
        let script = fs::read_to_string(wrapper).unwrap();
        assert!(script.contains("launch --agent codex"));
        assert!(script.contains("--real /opt/homebrew/bin/codex"));
    }

    #[test]
    fn real_agent_candidate_respects_path_order_and_skips_wrappers() {
        let dir = tempfile::tempdir().unwrap();
        let wrapper = dir.path().join("codex");
        let launcher = dir.path().join("launcher-codex");
        let real = dir.path().join("real-codex");
        write_launcher_script(
            &launcher,
            Path::new("/tmp/prompt-parole"),
            "codex",
            Path::new("/opt/homebrew/bin/codex"),
        )
        .unwrap();
        fs::write(&wrapper, "#!/bin/sh\n").unwrap();
        fs::write(&real, "#!/bin/sh\n").unwrap();

        let lines = [
            wrapper.to_string_lossy().to_string(),
            launcher.to_string_lossy().to_string(),
            real.to_string_lossy().to_string(),
        ];
        let selected = first_real_agent_candidate(lines.iter().map(String::as_str), &wrapper);

        assert_eq!(selected, Some(real));
    }

    #[test]
    fn input_guard_blocks_prompt_entry_but_allows_navigation_keys() {
        assert!(should_block_guard_key(0, 0));
        assert!(should_block_guard_key(GUARD_KEY_RETURN, 0));
        assert!(should_block_guard_key(GUARD_KEY_ENTER, 0));
        assert!(should_block_guard_key(GUARD_KEY_V, GUARD_FLAG_COMMAND));
        assert!(should_block_guard_key(GUARD_KEY_J, GUARD_FLAG_CONTROL));
        assert!(should_block_guard_key(GUARD_KEY_M, GUARD_FLAG_CONTROL));
        assert!(should_block_guard_key(0, GUARD_FLAG_OPTION));

        assert!(!should_block_guard_key(8, GUARD_FLAG_COMMAND));
        assert!(!should_block_guard_key(8, GUARD_FLAG_CONTROL));
        assert!(!should_block_guard_key(53, 0));
        assert!(!should_block_guard_key(123, 0));
        assert!(!should_block_guard_key(124, 0));
    }

    #[test]
    fn guard_agent_plist_escapes_paths_and_keeps_label() {
        let plist = launch_agent_plist(
            GUARD_AGENT_LABEL,
            Path::new("/tmp/prompt&parole"),
            &["guard"],
            Path::new("/tmp/out<log>"),
            Path::new("/tmp/err\"log\""),
        );

        assert!(plist.contains("<string>com.prompt-parole.guard</string>"));
        assert!(plist.contains("<string>/tmp/prompt&amp;parole</string>"));
        assert!(plist.contains("<string>/tmp/out&lt;log&gt;</string>"));
        assert!(plist.contains("<string>/tmp/err&quot;log&quot;</string>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
    }

    #[test]
    fn guard_watchdog_plist_runs_watchdog_command() {
        let plist = launch_agent_plist(
            GUARD_WATCHDOG_LABEL,
            Path::new("/tmp/prompt-parole"),
            &["guard-watchdog", "--interval-seconds", "2"],
            Path::new("/tmp/watchdog.log"),
            Path::new("/tmp/watchdog.err.log"),
        );

        assert!(plist.contains("<string>com.prompt-parole.guard-watchdog</string>"));
        assert!(plist.contains("<string>guard-watchdog</string>"));
        assert!(plist.contains("<string>--interval-seconds</string>"));
        assert!(plist.contains("<string>2</string>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
    }

    #[test]
    fn macos_app_plist_uses_prompt_parole_identity() {
        let plist = macos_app_info_plist();
        assert!(plist.contains("<key>CFBundleDisplayName</key>"));
        assert!(plist.contains("<string>Prompt Parole</string>"));
        assert!(plist.contains("<key>CFBundleExecutable</key>"));
        assert!(plist.contains("<string>prompt-parole</string>"));
        assert!(plist.contains("<key>CFBundlePackageType</key>"));
        assert!(plist.contains("<string>APPL</string>"));
    }

    #[test]
    fn protection_command_statuses_are_human_readable() {
        assert_eq!(protection_command_status(true, true), "Protected");
        assert_eq!(protection_command_status(true, false), "Not first in PATH");
        assert_eq!(protection_command_status(false, false), "Needs install");
    }

    #[test]
    fn app_tab_names_parse_for_debug_screenshots() {
        assert_eq!(AppTab::from_name("status"), Some(AppTab::Status));
        assert_eq!(AppTab::from_name("Protection"), Some(AppTab::Protection));
        assert_eq!(AppTab::from_name("unknown"), None);
    }

    #[test]
    fn front_window_matching_targets_terminal_agent_titles() {
        assert!(window_is_agent_target(
            "Terminal",
            "pb -- pb -- codex -- 131x35"
        ));
        assert!(window_is_agent_target(
            "Terminal",
            "work -- claude -- 100x40"
        ));
        assert!(window_is_agent_target("Codex", "workspace"));
        assert!(!window_is_agent_target("Terminal", "plain zsh"));
        assert!(!window_is_agent_target("Google Chrome", "codex docs"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescript_escape_handles_quotes_and_backslashes() {
        assert_eq!(
            applescript_string_escape(r#"/tmp/prompt "parole" \ guard"#),
            r#"/tmp/prompt \"parole\" \\ guard"#
        );
    }

    #[test]
    fn guard_process_parser_matches_only_real_guard_command() {
        assert_eq!(
            parse_prompt_parole_process_line(
                "123 /Users/jake/.local/bin/prompt-parole guard",
                "999",
                "guard"
            ),
            Some(123)
        );
        assert_eq!(
            parse_prompt_parole_process_line(
                "124 /Users/jake/.local/bin/prompt-parole guard-agent --action stop",
                "999",
                "guard"
            ),
            None
        );
        assert_eq!(
            parse_prompt_parole_process_line(
                "125 /bin/zsh -c /Users/jake/.local/bin/prompt-parole guard",
                "999",
                "guard"
            ),
            None
        );
        assert_eq!(
            parse_prompt_parole_process_line(
                "126 /Users/jake/.local/bin/prompt-parole guard",
                "126",
                "guard"
            ),
            None
        );
        assert_eq!(
            parse_prompt_parole_process_line(
                "127 /Users/jake/.local/bin/prompt-parole guard-watchdog",
                "999",
                "guard"
            ),
            None
        );
        assert_eq!(
            parse_prompt_parole_process_line(
                "128 /Users/jake/.local/bin/prompt-parole guard-watchdog",
                "999",
                "guard-watchdog"
            ),
            Some(128)
        );
    }

    #[test]
    fn nippon_palette_values_are_stable() {
        assert_eq!(shironeri(), egui::Color32::from_rgb(252, 250, 242));
        assert_eq!(torinoko(), egui::Color32::from_rgb(249, 191, 69));
        assert_eq!(seiji(), egui::Color32::from_rgb(129, 156, 139));
        assert_eq!(aomidori(), egui::Color32::from_rgb(58, 105, 96));
        assert_eq!(asagi(), egui::Color32::from_rgb(72, 146, 155));
        assert_eq!(yamabuki(), egui::Color32::from_rgb(255, 164, 0));
        assert_eq!(enji(), egui::Color32::from_rgb(157, 41, 51));
        assert_eq!(sumi(), egui::Color32::from_rgb(39, 34, 31));
    }
}
