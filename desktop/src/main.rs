use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Datelike, Duration, Local, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use clap::{Parser, Subcommand};
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
        if agent != "codex" && agent != "claude-code" {
            return Err(format!("Unsupported agent {agent:?}."));
        }
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
    current: String,
    new_first: String,
    new_again: String,
    setup_first: String,
    setup_again: String,
    unlock: String,
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
            &self.passwords.current,
            windows,
            self.timezone.clone(),
            self.unlock_duration_minutes,
            self.password_actions.clone(),
        ) {
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
            .change_password(&self.passwords.current, &self.passwords.new_first)
        {
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
        match self.core.lock() {
            Ok(_) => {
                self.reload();
                self.status_line = "Temporary unlock cleared.".to_owned();
            }
            Err(err) => self.error = err,
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
                        egui::RichText::new(format!("Config {}", self.app_dir.display()))
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
        section_frame().show(ui, |ui| {
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

        ui.add_space(14.0);
        section_frame().show(ui, |ui| {
            section_title(ui, "Temporary Unlock");
            form_grid(ui, "unlock-form", |ui| {
                password_editor(ui, "Password", &mut self.passwords.unlock);
                ui.label("Duration");
                ui.add(
                    egui::DragValue::new(&mut self.unlock_request_minutes)
                        .range(1..=1440)
                        .suffix(" min"),
                );
                ui.end_row();
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
    }
}

fn settings_editor(
    ui: &mut egui::Ui,
    timezone: &mut String,
    unlock_duration_minutes: &mut i64,
    windows: &mut Vec<WindowDraft>,
    password_actions: &mut Vec<String>,
) {
    subsection_title(ui, "Global Lock Schedule");
    let mut remove_index = None;
    let time_options = time_options(windows);
    let can_remove = windows.len() > 1;
    for (index, window) in windows.iter_mut().enumerate() {
        lock_window_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                let label = if index == 0 {
                    "Curfew".to_owned()
                } else {
                    format!("Extra range {}", index + 1)
                };
                ui.label(egui::RichText::new(label).strong().color(sumi()));
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
    if secondary_button(ui, "Add Time Range").clicked() {
        windows.push(WindowDraft::default());
    }

    ui.add_space(14.0);
    subsection_title(ui, "General");
    form_grid(ui, "general-settings", |ui| {
        ui.label("Timezone");
        ui.add(egui::TextEdit::singleline(timezone).desired_width(180.0));
        ui.end_row();
        ui.label("Default unlock");
        ui.add(
            egui::DragValue::new(unlock_duration_minutes)
                .range(1..=1440)
                .suffix(" min"),
        );
        ui.end_row();
    });
    meta_label(ui, "Password required for");
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

fn password_editor(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .desired_width(230.0),
    );
    ui.end_row();
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
