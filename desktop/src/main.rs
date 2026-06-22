use base64::{Engine as _, engine::general_purpose};
use chrono::{
    DateTime, Datelike, Duration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone, Utc,
};
use chrono_tz::Tz;
use clap::{Parser, Subcommand, ValueEnum};
use constant_time_eq::constant_time_eq;
use eframe::egui;
use rand::Rng;
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration as StdDuration, Instant};

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
/// Upper bound on a temporary unlock (one year) — also the GUI duration control's max.
const MAX_UNLOCK_MINUTES: i64 = 366 * 24 * 60;
const PASSWORD_ACTIONS: [&str; 6] = [
    "configure",
    "disable",
    "install",
    "passwd",
    "uninstall",
    "unlock",
];
const HARD_PASSWORD_ACTIONS: [&str; 3] = ["configure", "passwd", "unlock"];
#[cfg(not(test))]
const SCRYPT_LOG_N: u8 = 15;
#[cfg(test)]
const SCRYPT_LOG_N: u8 = 10;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DKLEN: usize = 32;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Config {
    // Defaulted so a config from a different version (added/missing optional fields)
    // still loads; normalize_config validates the result afterward.
    #[serde(default)]
    version: i64,
    timezone: String,
    unlock_duration_minutes: i64,
    password_required_for: Vec<String>,
    lock_windows: Vec<LockWindow>,
    #[serde(default)]
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
        if let Ok(raw) = fs::read_to_string(&path) {
            match serde_json::from_str(&raw) {
                Ok(state) => return state,
                Err(err) => {
                    // A corrupt state file drops any active temporary unlock (it
                    // re-locks, the safe direction). decision() runs in hot loops
                    // (guard poll, GUI refresh), so warn only once per process.
                    static WARNED: AtomicBool = AtomicBool::new(false);
                    if !WARNED.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "prompt-parole: ignoring unreadable {} ({err}); treating as locked.",
                            path.display()
                        );
                    }
                }
            }
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
        // Cap at one year so a huge value cannot overflow chrono's date math (which
        // would otherwise panic).
        if duration_minutes > MAX_UNLOCK_MINUTES {
            return Err("Unlock duration must be at most one year.".to_owned());
        }
        let config = self.load_config()?;
        let expires = now_for_config(&config)?
            .checked_add_signed(Duration::minutes(duration_minutes))
            .ok_or_else(|| "Unlock duration is out of range.".to_owned())?;
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
        // When unconfigured, allow regardless of the agent name (a typo'd --agent
        // on an unconfigured machine must not block).
        if !self.is_configured() {
            return Ok(None);
        }
        // An unknown agent name still follows the (global) curfew rather than
        // erroring — an unrecognized --agent must not block prompts 24/7.
        let normalized = normalized_hook_agent(agent).ok();
        let decision = self.decision()?;
        if decision.allowed {
            return Ok(None);
        }
        append_event(
            &self.events_path(),
            serde_json::json!({"event": "prompt_blocked", "agent": normalized.unwrap_or(agent)}),
        );
        let until = decision
            .locked_until
            .map(|value| value.format("%Y-%m-%d %H:%M %Z").to_string())
            .unwrap_or_else(|| "the scheduled unlock time".to_owned());
        let mut payload = serde_json::json!({
            "decision": "block",
            "reason": format!("Prompt Parole: curfew is active until {until}. You can inspect progress, but new prompts need `prompt-parole unlock`.")
        });
        if normalized == Some("claude-code") {
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
    for window in &mut config.lock_windows {
        // Canonicalize so comparison/storage are by actual time, not raw string.
        window.start = canonical_hhmm(&window.start)?;
        window.end = canonical_hhmm(&window.end)?;
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
    let start = canonical_hhmm(start)?;
    let end = canonical_hhmm(end)?;
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
    Ok(LockWindow { start, end, days })
}

fn parse_hhmm(value: &str) -> Result<NaiveTime, String> {
    NaiveTime::parse_from_str(value, "%H:%M")
        .map_err(|_| format!("Invalid time {value:?}; expected HH:MM."))
}

/// Parse a time and return its canonical `HH:MM` form, so equality/storage are by
/// actual time rather than by raw string (e.g. "9:00" and "09:00" are the same).
fn canonical_hhmm(value: &str) -> Result<String, String> {
    Ok(parse_hhmm(value)?.format("%H:%M").to_string())
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
    // Evaluate against the real time zone (not a frozen offset) so DST transitions
    // inside a curfew window resolve each wall-clock boundary at its own offset.
    if config.timezone == "local" {
        evaluate_in_zone(config, state, Local::now())
    } else {
        let tz = config
            .timezone
            .parse::<Tz>()
            .map_err(|_| format!("Unknown timezone {:?}.", config.timezone))?;
        evaluate_in_zone(config, state, Utc::now().with_timezone(&tz))
    }
}

fn evaluate_in_zone<Z: TimeZone>(
    config: &Config,
    state: &State,
    now: DateTime<Z>,
) -> Result<Decision, String> {
    let locked_until = scheduled_lock_until(config, now.clone())?;
    let unlock_expires_at = state
        .unlock_expires_at
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
    let now_utc = now.to_utc();
    let scheduled_locked = locked_until.is_some();
    let temporarily_unlocked = unlock_expires_at.is_some_and(|value| now_utc < value.to_utc());
    let locked_until = locked_until.map(|value| value.fixed_offset());
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

fn scheduled_lock_until<Z: TimeZone>(
    config: &Config,
    now: DateTime<Z>,
) -> Result<Option<DateTime<Z>>, String> {
    let tz = now.timezone();
    let mut matching: Vec<DateTime<Z>> = Vec::new();
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
            // On an ambiguous (fall-back) hour, bias toward more locking: resolve
            // the start to the earliest instant and the end to the latest, so the
            // curfew can never lift early.
            let start_dt = resolve_in_zone(&tz, start_naive, false);
            let end_dt = resolve_in_zone(&tz, end_naive, true);
            if start_dt <= now && now < end_dt {
                matching.push(end_dt);
            }
        }
    }
    Ok(matching.into_iter().max())
}

/// Convert a wall-clock time to an instant in `tz`, handling DST transitions. For
/// an ambiguous fall-back hour, pick the later instant when `prefer_later` (curfew
/// end) else the earlier (curfew start). Across a spring-forward gap (always <=1h),
/// skip forward to the first valid instant.
fn resolve_in_zone<Z: TimeZone>(tz: &Z, naive: NaiveDateTime, prefer_later: bool) -> DateTime<Z> {
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(dt) => dt,
        LocalResult::Ambiguous(earliest, latest) => {
            if prefer_later {
                latest
            } else {
                earliest
            }
        }
        LocalResult::None => {
            // Spring-forward gap: the wall time does not exist. Step forward minute
            // by minute to the first instant that does — the moment the clock jumps —
            // so a boundary in the gap maps to the transition, not up to an hour off.
            let mut probe = naive;
            let limit = naive + Duration::hours(2);
            loop {
                probe += Duration::minutes(1);
                if let LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) =
                    tz.from_local_datetime(&probe)
                {
                    break dt;
                }
                if probe >= limit {
                    break tz.from_utc_datetime(&naive);
                }
            }
        }
    }
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
    let mut output = vec![0_u8; SCRYPT_DKLEN];
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
        .map_err(|err| format!("Invalid scrypt params: {err}"))?;
    scrypt(password.as_bytes(), &salt, &params, &mut output)
        .map_err(|err| format!("Could not hash password: {err}"))?;
    Ok(Secret {
        version: 1,
        kdf: "scrypt".to_owned(),
        params: SecretParams {
            n: 2_u32.pow(SCRYPT_LOG_N as u32),
            r: SCRYPT_R,
            p: SCRYPT_P,
            dklen: SCRYPT_DKLEN,
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
    // Derive to the stored hash's actual length, not the separate `dklen` field:
    // scrypt() uses output.len(), so a corrupted dklen must not cause a length
    // mismatch that rejects the correct password forever. A hash whose length
    // scrypt won't accept (corrupt secret) is treated as a non-match, not an error,
    // so it surfaces as "incorrect password" rather than a hard failure.
    let Ok(params) = ScryptParams::new(log_n, secret.params.r, secret.params.p, expected.len())
    else {
        return Ok(false);
    };
    let mut output = vec![0_u8; expected.len()];
    if scrypt(password.as_bytes(), &salt, &params, &mut output).is_err() {
        return Ok(false);
    }
    Ok(constant_time_eq(&output, &expected))
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        // Create the directory already restricted to the user (0700) so there is
        // no window where the secrets directory is group/world-traversable.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|err| format!("Could not create {}: {err}", path.display()))?;
        // If it already existed with wider permissions, tighten it now.
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("Could not secure {}: {err}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
            .map_err(|err| format!("Could not create {}: {err}", path.display()))?;
    }
    Ok(())
}

/// Write app-owned secret/config/state durably and privately (dir 0700, file 0600).
fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory.", path.display()))?;
    ensure_private_dir(parent)?;
    persist_json_atomic(path, parent, value, Some(0o600))
}

/// Write into a config file we do not own (e.g. ~/.claude/settings.json) without
/// tightening the directory or the file's existing permissions.
fn write_json_shared<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    // If the destination is a symlink (common when settings.json/hooks.json are
    // managed by a dotfiles tool like stow/chezmoi/yadm), write THROUGH it to the real
    // target. Otherwise the atomic rename below would replace the symlink with a plain
    // file and silently detach the tracked config.
    let resolved = resolve_symlink_target(path);
    let target = resolved.as_deref().unwrap_or(path);
    let parent = target
        .parent()
        .ok_or_else(|| format!("{} has no parent directory.", target.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("Could not create {}: {err}", parent.display()))?;
    let preserve = existing_file_mode(target);
    persist_json_atomic(target, parent, value, preserve)
}

/// If `path` is a symlink, follow the chain to the final target path (which may not
/// exist yet) so shared-config writers replace the target file rather than clobbering
/// the link. Returns None when `path` is not a symlink or a cycle/too-deep chain is hit
/// (in which case the caller falls back to treating `path` as the destination).
fn resolve_symlink_target(path: &Path) -> Option<PathBuf> {
    if !fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return None;
    }
    let mut current = path.to_path_buf();
    // Bounded so a symlink cycle cannot spin forever.
    for _ in 0..40 {
        let link = fs::read_link(&current).ok()?;
        let resolved = if link.is_absolute() {
            link
        } else {
            match current.parent() {
                Some(parent) => parent.join(link),
                None => link,
            }
        };
        match fs::symlink_metadata(&resolved) {
            Ok(m) if m.file_type().is_symlink() => current = resolved,
            // Final target: a non-symlink that exists, or a path that doesn't exist yet.
            _ => return Some(resolved),
        }
    }
    None
}

#[cfg(unix)]
fn existing_file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .ok()
        .map(|meta| meta.permissions().mode())
}

#[cfg(not(unix))]
fn existing_file_mode(_path: &Path) -> Option<u32> {
    None
}

fn persist_json_atomic<T: Serialize>(
    path: &Path,
    parent: &Path,
    value: &T,
    mode: Option<u32>,
) -> Result<(), String> {
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("Could not create temp file for {}: {err}", path.display()))?;
    serde_json::to_writer_pretty(&mut temp, value)
        .map_err(|err| format!("Could not write JSON: {err}"))?;
    temp.write_all(b"\n")
        .map_err(|err| format!("Could not finish JSON: {err}"))?;
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|err| format!("Could not set permissions on temp file: {err}"))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    // Flush file data to disk before the rename so a crash cannot leave the
    // destination present but empty/partial.
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("Could not flush {}: {err}", path.display()))?;
    temp.persist(path)
        .map_err(|err| format!("Could not replace {}: {}", path.display(), err.error))?;
    // Flush the rename itself so the new file is durably linked into the directory.
    sync_dir(parent);
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

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
        // Compare by parsed time so non-canonical equals (e.g. 9:00 / 09:00) are caught.
        if parse_hhmm(&self.start)? == parse_hhmm(&self.end)? {
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
    vscode_guarded: bool,
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

/// Messages from background worker/refresher threads back to the UI thread.
enum AppEvent {
    /// Periodic live refresh of lock status and protection (never touches the
    /// editable fields the user may be mid-edit on).
    Refresh {
        /// Value of `action_epoch` when this refresh was snapshotted. The pump rejects
        /// the refresh if an action has completed since (the epoch advanced), so a slow
        /// pre-action snapshot can't clobber a fresh post-action state in a later batch.
        epoch: u64,
        configured: bool,
        status: Option<StatusPayload>,
        protection: ProtectionStatus,
    },
    /// A user-triggered action finished.
    ActionDone {
        outcome: Result<String, String>,
        configured: bool,
        config: Config,
        status: Option<StatusPayload>,
        protection: ProtectionStatus,
        reset_editors: bool,
    },
}

struct PromptParoleApp {
    core: ParoleCore,
    app_dir: PathBuf,
    config: Config,
    configured: bool,
    status: Option<StatusPayload>,
    notice: String,
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
    busy: Option<String>,
    /// Monotonic counter bumped each time an action settles; lets the pump reject a
    /// background refresh that was snapshotted before a since-completed action.
    action_epoch: Arc<AtomicU64>,
    events_tx: mpsc::Sender<AppEvent>,
    events_rx: mpsc::Receiver<AppEvent>,
    refresher_started: bool,
    style_applied: bool,
    viewport_normalized: bool,
}

impl PromptParoleApp {
    fn new() -> Self {
        let app_dir = app_dir();
        let core = ParoleCore {
            app_dir: app_dir.clone(),
        };
        let (events_tx, events_rx) = mpsc::channel();
        let mut app = Self {
            core,
            app_dir,
            config: default_config(),
            configured: false,
            status: None,
            notice: String::new(),
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
            busy: None,
            action_epoch: Arc::new(AtomicU64::new(0)),
            events_tx,
            events_rx,
            refresher_started: false,
            style_applied: false,
            viewport_normalized: false,
        };
        app.reload();
        app
    }

    /// Full synchronous load — used once at startup. All later refreshes happen on
    /// background threads so the UI never blocks.
    fn reload(&mut self) {
        self.configured = self.core.is_configured();
        let config = self.core.load_config().unwrap_or_else(|_| default_config());
        self.apply_config_to_editors(&config);
        self.status = if self.configured {
            self.core.status().ok()
        } else {
            None
        };
        // Protection status spawns `ps` and probes the login shell, which can block
        // for up to a few seconds. Leave it at default here so the first frame paints
        // instantly; the background refresher fills it in on its first pass.
    }

    fn apply_config_to_editors(&mut self, config: &Config) {
        self.timezone = config.timezone.clone();
        self.unlock_duration_minutes = config.unlock_duration_minutes;
        self.unlock_request_minutes = config.unlock_duration_minutes;
        self.password_actions = normalized_actions(&config.password_required_for);
        self.windows = if config.lock_windows.is_empty() {
            vec![WindowDraft::default()]
        } else {
            config
                .lock_windows
                .iter()
                .map(WindowDraft::from_window)
                .collect()
        };
        self.config = config.clone();
    }

    fn clear_password_inputs(&mut self) {
        self.passwords = PasswordFields::default();
        self.generated_password.clear();
    }

    /// Cheap status-only refresh for the manual Refresh button (no process scan).
    fn refresh_status_now(&mut self) {
        self.configured = self.core.is_configured();
        self.status = if self.configured {
            self.core.status().ok()
        } else {
            None
        };
    }

    /// Start the background refresher (once) and drain pending worker messages.
    fn pump(&mut self, ctx: &egui::Context) {
        if !self.refresher_started {
            self.refresher_started = true;
            let tx = self.events_tx.clone();
            let core = self.core.clone();
            let ctx = ctx.clone();
            let action_epoch = Arc::clone(&self.action_epoch);
            thread::spawn(move || {
                loop {
                    // Capture the epoch BEFORE the (slow) snapshot so the pump can reject
                    // this refresh if an action completes while we are computing it.
                    let epoch = action_epoch.load(Ordering::SeqCst);
                    let configured = core.is_configured();
                    let status = if configured { core.status().ok() } else { None };
                    let protection = protection_status();
                    if tx
                        .send(AppEvent::Refresh {
                            epoch,
                            configured,
                            status,
                            protection,
                        })
                        .is_err()
                    {
                        break; // UI gone; stop the thread.
                    }
                    ctx.request_repaint();
                    thread::sleep(StdDuration::from_millis(1500));
                }
            });
        }
        // Drain everything, then apply Refreshes before ActionDones so an action's
        // fresh result always wins over a background Refresh that was computed
        // before the action landed and merely arrived in the same batch.
        let mut events: Vec<AppEvent> = Vec::new();
        while let Ok(event) = self.events_rx.try_recv() {
            events.push(event);
        }
        let has_action = events
            .iter()
            .any(|event| matches!(event, AppEvent::ActionDone { .. }));
        events.sort_by_key(|event| matches!(event, AppEvent::ActionDone { .. }));
        for event in events {
            match event {
                AppEvent::Refresh {
                    epoch,
                    configured,
                    status,
                    protection,
                } => {
                    // Skip background refreshes that are stale: while an action is
                    // settling, one completed this batch, OR one completed since this
                    // refresh was snapshotted (the epoch advanced). The epoch check
                    // closes the cross-batch window the busy/has_action gates miss.
                    if self.busy.is_none()
                        && !has_action
                        && epoch == self.action_epoch.load(Ordering::SeqCst)
                    {
                        self.configured = configured;
                        self.status = status;
                        self.protection = protection;
                    }
                }
                AppEvent::ActionDone {
                    outcome,
                    configured,
                    config,
                    status,
                    protection,
                    reset_editors,
                } => {
                    self.busy = None;
                    self.configured = configured;
                    self.status = status;
                    self.protection = protection;
                    match outcome {
                        Ok(notice) => {
                            self.notice = notice;
                            self.error.clear();
                            self.clear_password_inputs();
                            if reset_editors {
                                self.apply_config_to_editors(&config);
                            } else {
                                self.config = config;
                            }
                        }
                        Err(err) => {
                            self.error = err;
                            self.notice.clear();
                        }
                    }
                }
            }
        }
    }

    /// Run a (possibly slow) action on a worker thread. The UI stays responsive and
    /// shows a busy indicator; the result arrives via [`AppEvent::ActionDone`].
    fn spawn_action<F>(&mut self, ctx: &egui::Context, label: &str, reset_editors: bool, job: F)
    where
        F: FnOnce(&ParoleCore) -> Result<String, String> + Send + 'static,
    {
        if self.busy.is_some() {
            return;
        }
        self.error.clear();
        self.notice.clear();
        self.busy = Some(label.to_owned());
        let core = self.core.clone();
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        let action_epoch = Arc::clone(&self.action_epoch);
        thread::spawn(move || {
            // Catch a panic in the job so the UI's busy flag always clears; a stuck
            // busy flag would disable the whole window permanently.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(&core)))
                .unwrap_or_else(|_| Err("The operation failed unexpectedly.".to_owned()));
            let configured = core.is_configured();
            let config = core.load_config().unwrap_or_else(|_| default_config());
            let status = if configured { core.status().ok() } else { None };
            let protection = protection_status();
            // Bump the epoch (after the fresh snapshot, before sending) so any refresh
            // snapshotted before this action is rejected by the pump as stale.
            action_epoch.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(AppEvent::ActionDone {
                outcome,
                configured,
                config,
                status,
                protection,
                reset_editors,
            });
            ctx.request_repaint();
        });
    }

    fn setup(&mut self, ctx: &egui::Context) {
        if self.passwords.setup_first != self.passwords.setup_again {
            self.error = "Passwords do not match.".to_owned();
            self.notice.clear();
            return;
        }
        let windows = match self.window_values() {
            Ok(values) => values,
            Err(err) => {
                self.error = err;
                self.notice.clear();
                return;
            }
        };
        let password = self.passwords.setup_first.clone();
        let timezone = self.timezone.clone();
        let duration = self.unlock_duration_minutes;
        let actions = self.password_actions.clone();
        self.spawn_action(ctx, "Setting up…", true, move |core| {
            core.setup(&password, windows, timezone, duration, actions)
                .map(|_| "Prompt Parole is ready.".to_owned())
        });
    }

    fn save_settings(&mut self, ctx: &egui::Context) {
        let windows = match self.window_values() {
            Ok(values) => values,
            Err(err) => {
                self.error = err;
                self.notice.clear();
                return;
            }
        };
        let password = self.passwords.settings_current.clone();
        let timezone = self.timezone.clone();
        let duration = self.unlock_duration_minutes;
        let actions = self.password_actions.clone();
        self.spawn_action(ctx, "Saving settings…", true, move |core| {
            core.configure(&password, windows, timezone, duration, actions)
                .map(|_| "Settings saved.".to_owned())
        });
    }

    fn unlock(&mut self, ctx: &egui::Context) {
        let password = self.passwords.unlock.clone();
        let minutes = self.unlock_request_minutes;
        self.spawn_action(ctx, "Unlocking…", false, move |core| {
            core.unlock(&password, minutes)
                .map(|expires| format!("Unlocked until {}.", expires.format("%Y-%m-%d %H:%M %Z")))
        });
    }

    fn change_password(&mut self, ctx: &egui::Context) {
        if self.passwords.new_first != self.passwords.new_again {
            self.error = "New passwords do not match.".to_owned();
            self.notice.clear();
            return;
        }
        let current = self.passwords.change_current.clone();
        let next = self.passwords.new_first.clone();
        self.spawn_action(ctx, "Changing password…", false, move |core| {
            core.change_password(&current, &next)
                .map(|_| "Password changed.".to_owned())
        });
    }

    fn manual_lock(&mut self, ctx: &egui::Context) {
        self.spawn_action(ctx, "Clearing unlock…", false, move |core| {
            core.lock().map(|_| "Temporary unlock cleared.".to_owned())
        });
    }

    fn install_protection(&mut self, ctx: &egui::Context) {
        let password = self.passwords.install_current.clone();
        self.spawn_action(ctx, "Installing protection…", false, move |core| {
            gui_install_protection(core, &password)
        });
    }

    fn start_input_guard(&mut self, ctx: &egui::Context) {
        self.spawn_action(ctx, "Starting input guard…", false, move |core| {
            start_guard_agent(core)
                .map(|()| "Input guard started.".to_owned())
                .map_err(|err| format!("Could not start input guard: {err}"))
        });
    }

    fn install_app_bundle(&mut self, ctx: &egui::Context) {
        self.spawn_action(ctx, "Installing app…", false, move |_core| {
            install_macos_app_bundle(None)
                .map(|path| format!("Installed app at {}.", path.display()))
                .map_err(|err| format!("Could not install app: {err}"))
        });
    }

    fn install_vscode(&mut self, ctx: &egui::Context) {
        let password = self.passwords.install_current.clone();
        self.spawn_action(ctx, "Covering VS Code…", false, move |core| {
            gui_require_install_password(core, &password)?;
            install_vscode_wrappers(core)
        });
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

/// Enforce the same "install" password gate the CLI uses, for GUI install actions.
fn gui_require_install_password(core: &ParoleCore, password: &str) -> Result<(), String> {
    if core.is_configured() {
        let config = core.load_config()?;
        if config.password_required_for.iter().any(|a| a == "install") {
            core.assert_password(password)?;
        }
    }
    Ok(())
}

/// Install hooks + launchers, honoring the same password gate the CLI uses.
fn gui_install_protection(core: &ParoleCore, password: &str) -> Result<String, String> {
    gui_require_install_password(core, password)?;
    let mut installed = 0;
    for target in ["claude", "codex"] {
        let path = target_path(target, None)?;
        let command = default_hook_command(&target_agent(target));
        install_json_hook(&path, &command, "Checking Prompt Parole curfew")?;
        install_launcher(target, None)?;
        installed += 1;
    }
    Ok(format!(
        "Installed hooks and launchers for {installed} tools. Restart Codex/Claude to apply."
    ))
}

impl eframe::App for PromptParoleApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if !self.style_applied {
            apply_style(ui.ctx());
            self.style_applied = true;
        }
        if !self.viewport_normalized {
            normalize_gui_viewport(ui.ctx());
            self.viewport_normalized = true;
        }
        self.pump(ui.ctx());

        egui::Frame::new()
            .fill(shironeri())
            .inner_margin(0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        centered_page(ui, |ui| {
                            app_header(ui, self.status.as_ref(), self.configured);
                            ui.add_space(14.0);

                            if let Some(label) = self.busy.clone() {
                                busy_banner(ui, &label);
                                ui.add_space(10.0);
                            } else if !self.notice.is_empty() {
                                notice_banner(ui, &self.notice);
                                ui.add_space(10.0);
                            }
                            if !self.error.is_empty() {
                                alert_frame().show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.colored_label(
                                        enji(),
                                        egui::RichText::new(&self.error).strong().size(14.0),
                                    );
                                });
                                ui.add_space(10.0);
                            }
                            ui.add_space(6.0);

                            // Disable interaction (but keep everything visible) while
                            // a background action is running.
                            let enabled = self.busy.is_none();
                            ui.scope(|ui| {
                                if !enabled {
                                    ui.disable();
                                }
                                if self.configured {
                                    self.configured_ui(ui);
                                } else {
                                    self.setup_ui(ui);
                                }
                            });
                        });
                    });
            });
    }
}

fn busy_banner(ui: &mut egui::Ui, label: &str) {
    egui::Frame::new()
        .fill(field())
        .stroke(egui::Stroke::new(1.0, asagi()))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(16.0).color(tokiwa()));
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(label)
                        .color(tokiwa())
                        .strong()
                        .size(14.0),
                );
            });
        });
}

fn notice_banner(ui: &mut egui::Ui, notice: &str) {
    egui::Frame::new()
        .fill(field())
        .stroke(egui::Stroke::new(1.0, seiji()))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                egui::RichText::new(notice)
                    .color(tokiwa())
                    .strong()
                    .size(13.5),
            );
        });
}

fn normalize_gui_viewport(ctx: &egui::Context) {
    // Open tall enough that the tallest tab (Schedule) shows without scrolling,
    // capped to the monitor so it stays on screen on small displays. The user can
    // still shrink it (min size below), and then the ScrollArea takes over.
    const TARGET_INNER_WIDTH: f32 = 760.0;
    const TARGET_INNER_HEIGHT: f32 = 840.0;
    let (width, height) = match ctx.input(|input| input.viewport().monitor_size) {
        Some(monitor) if monitor.x > 0.0 && monitor.y > 0.0 => (
            TARGET_INNER_WIDTH.min(monitor.x * 0.95),
            TARGET_INNER_HEIGHT.min(monitor.y * 0.9),
        ),
        _ => (TARGET_INNER_WIDTH, TARGET_INNER_HEIGHT),
    };
    ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(
        620.0_f32.min(width),
        360.0,
    )));
    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(width, height)));
    // Do NOT force OuterPosition: that overrides eframe's `centered` placement and
    // can push the window off-screen. Let the window stay where eframe centered it.
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
                        tokiwa()
                    } else {
                        egui::Color32::TRANSPARENT
                    };
                    let text_color = if selected { button_fg() } else { tokiwa() };
                    let response = ui.add(
                        egui::Button::new(
                            egui::RichText::new(tab.label())
                                .size(13.5)
                                .strong()
                                .color(text_color),
                        )
                        .fill(fill)
                        .stroke(egui::Stroke::new(1.0, tokiwa()))
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
        let first = vertical_password_editor(ui, "Password", &mut app.passwords.setup_first);
        ui.add_space(8.0);
        let again = vertical_password_editor(ui, "Password again", &mut app.passwords.setup_again);
        ui.add_space(12.0);
        password_suggestion(ui, app);
        ui.add_space(16.0);
        let enter = submitted_with_enter(ui, &first) || submitted_with_enter(ui, &again);
        if full_primary_button(ui, "Start Parole").clicked() || enter {
            app.setup(ui.ctx());
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
                    app.refresh_status_now();
                }
                if primary_button(ui, "Start Input Guard").clicked() {
                    app.start_input_guard(ui.ctx());
                }
            });
        });
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if compact_secondary_button(ui, "Permission Settings").clicked() {
                open_input_monitoring_settings();
            }
            ui.add_space(6.0);
            meta_label(
                ui,
                "Runs as the app — no Terminal. Needs Input Monitoring permission to block keys.",
            );
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
            let password = vertical_password_editor(
                ui,
                "Password for settings",
                &mut app.passwords.settings_current,
            );
            ui.add_space(10.0);
            let enter = submitted_with_enter(ui, &password);
            if full_primary_button(ui, "Save Settings").clicked() || enter {
                app.save_settings(ui.ctx());
            }
        }
    });
}

fn unlock_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Temporary Unlock");
        let password = vertical_password_editor(ui, "Password", &mut app.passwords.unlock);
        ui.add_space(8.0);
        labeled_duration(ui, "Duration", &mut app.unlock_request_minutes);
        ui.add_space(14.0);
        let enter = submitted_with_enter(ui, &password);
        if full_primary_button(ui, "Unlock Temporarily").clicked() || enter {
            app.unlock(ui.ctx());
        }
        if let Some(status) = &app.status {
            ui.add_space(10.0);
            if let Some(value) = &status.locked_until {
                meta_label(ui, format!("Scheduled lock ends: {}", pretty_time(value)));
            }
            if let Some(value) = &status.unlock_expires_at {
                meta_label(
                    ui,
                    format!("Temporary unlock expires: {}", pretty_time(value)),
                );
            }
        }
    });
}

fn password_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Password");
        let current =
            vertical_password_editor(ui, "Current password", &mut app.passwords.change_current);
        ui.add_space(8.0);
        let next = vertical_password_editor(ui, "New password", &mut app.passwords.new_first);
        ui.add_space(8.0);
        let again =
            vertical_password_editor(ui, "New password again", &mut app.passwords.new_again);
        ui.add_space(12.0);
        password_suggestion(ui, app);
        ui.add_space(10.0);
        let enter = submitted_with_enter(ui, &current)
            || submitted_with_enter(ui, &next)
            || submitted_with_enter(ui, &again);
        if full_primary_button(ui, "Change Password").clicked() || enter {
            app.change_password(ui.ctx());
        }
    });
}

fn manual_lock_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Manual Lock");
        if full_secondary_button(ui, "Clear Temporary Unlock").clicked() {
            app.manual_lock(ui.ctx());
        }
    });
}

fn protection_card(ui: &mut egui::Ui, app: &mut PromptParoleApp) {
    section_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Protection");
        protection_summary(ui, &app.protection);
        ui.add_space(12.0);
        let password = vertical_password_editor(
            ui,
            "Password for install",
            &mut app.passwords.install_current,
        );
        ui.add_space(10.0);
        let enter = submitted_with_enter(ui, &password);
        if full_secondary_button(ui, "Install Hooks & Launchers").clicked() || enter {
            app.install_protection(ui.ctx());
        }
        meta_label(ui, "Protect future Codex and Claude sessions.");
        meta_label(
            ui,
            "Codex enforces via the launcher; its prompt hook also needs to be trusted inside Codex.",
        );
        ui.add_space(8.0);
        if full_secondary_button(ui, "Cover VS Code Extensions").clicked() {
            app.install_vscode(ui.ctx());
        }
        meta_label(
            ui,
            "Gate the Claude Code & Codex VS Code extensions (reload VS Code after).",
        );
        ui.add_space(8.0);
        if full_secondary_button(ui, "Install Mac App").clicked() {
            app.install_app_bundle(ui.ctx());
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

/// True if the user pressed Enter while this field had focus (login-form muscle
/// memory: type a password, hit Enter to submit).
fn submitted_with_enter(ui: &egui::Ui, response: &egui::Response) -> bool {
    response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter))
}

fn vertical_password_editor(ui: &mut egui::Ui, label: &str, value: &mut String) -> egui::Response {
    field_label(ui, label);
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .desired_width(ui.available_width()),
    )
}

/// A minutes field with quick presets. Clearer than a bare DragValue, which users
/// often do not realize is editable.
fn labeled_duration(ui: &mut egui::Ui, label: &str, value: &mut i64) {
    field_label(ui, label);
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::DragValue::new(value)
                .range(1..=MAX_UNLOCK_MINUTES)
                .suffix(" min")
                .speed(1),
        );
        ui.add_space(6.0);
        for (caption, minutes) in [("15m", 15), ("30m", 30), ("1h", 60), ("2h", 120)] {
            let selected = *value == minutes;
            let fill = if selected {
                tokiwa()
            } else {
                egui::Color32::TRANSPARENT
            };
            let text_color = if selected { button_fg() } else { tokiwa() };
            let response = ui.add(
                egui::Button::new(egui::RichText::new(caption).size(12.5).color(text_color))
                    .fill(fill)
                    .stroke(egui::Stroke::new(1.0, tokiwa()))
                    .corner_radius(egui::CornerRadius::same(6))
                    .min_size(egui::vec2(40.0, 26.0)),
            );
            if response.clicked() {
                *value = minutes;
            }
        }
    });
}

fn field_label(ui: &mut egui::Ui, label: &str) {
    ui.label(egui::RichText::new(label).size(13.0).strong().color(nibi()));
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
        .fill(tokiwa())
        .stroke(egui::Stroke::new(1.0, tokiwa()))
        .corner_radius(egui::CornerRadius::same(6)),
    )
}

fn full_secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add_sized(
        [ui.available_width(), 34.0],
        egui::Button::new(
            egui::RichText::new(label)
                .color(tokiwa())
                .strong()
                .size(14.0),
        )
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, tokiwa()))
        .corner_radius(egui::CornerRadius::same(6)),
    )
}

fn compact_secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .color(tokiwa())
                .strong()
                .size(13.0),
        )
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, tokiwa()))
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
    ui.vertical(|ui| {
        ui.set_width(ui.available_width());
        field_label(ui, "Timezone");
        ui.add(egui::TextEdit::singleline(timezone).desired_width(220.0));
        ui.add_space(10.0);
        labeled_duration(ui, "Default unlock", unlock_duration_minutes);
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
                    .color(tokiwa())
                    .strong(),
            );
        }
    });
    meta_label(
        ui,
        "No recovery command. Keep the password somewhere recoverable.",
    );
}

fn app_header(ui: &mut egui::Ui, status: Option<&StatusPayload>, configured: bool) {
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
    ui.add_space(6.0);
    // A thin hairline rule under the title (replaces the old decorative palette bar).
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 1.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, line());
}

/// (text, background, foreground) for the live status pill.
fn pill_style(
    status: Option<&StatusPayload>,
    configured: bool,
) -> (&'static str, egui::Color32, egui::Color32) {
    if !configured {
        return ("Not configured", yamabuki(), sumi());
    }
    match status {
        Some(status) if status.allowed => ("Prompts allowed", tokiwa(), button_fg()),
        Some(_) => ("Prompts blocked", enji(), button_fg()),
        None => ("Status unavailable", nibi(), button_fg()),
    }
}

fn status_pill(ui: &mut egui::Ui, status: Option<&StatusPayload>, configured: bool) {
    let (text, fill, text_color) = pill_style(status, configured);
    egui::Frame::new()
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(16))
        .inner_margin(egui::Margin::symmetric(12, 6))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(text)
                    .color(text_color)
                    .strong()
                    .size(13.5),
            );
        });
}

fn status_summary(ui: &mut egui::Ui, status: &StatusPayload) {
    let (label, color) = if status.allowed {
        ("PROMPTS ALLOWED", tokiwa())
    } else {
        ("PROMPTS BLOCKED", enji())
    };
    ui.label(egui::RichText::new(label).size(18.0).strong().color(color));
    meta_label(ui, status.reason.as_str());
    if let Some(value) = &status.locked_until {
        meta_label(ui, format!("Lock ends {}", pretty_time(value)));
    }
    if let Some(value) = &status.unlock_expires_at {
        meta_label(ui, format!("Temporary unlock until {}", pretty_time(value)));
    }
}

/// Format an RFC3339 timestamp as a friendly local-ish string; fall back to raw.
fn pretty_time(rfc3339: &str) -> String {
    DateTime::parse_from_rfc3339(rfc3339)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|_| rfc3339.to_owned())
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
        "VS Code extensions",
        protection
            .vscode_guarded
            .then_some("Ready after reload")
            .or(Some("Needs setup")),
        None,
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
        "Protected" | "Installed" | "Ready after restart" | "Ready after reload" => tokiwa(),
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
            .color(tokiwa()),
    );
    ui.add_space(4.0);
}

fn meta_label(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(egui::RichText::new(text.into()).color(nibi()).size(13.0));
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
        .fill(tokiwa())
        .stroke(egui::Stroke::new(1.0, tokiwa()))
        .corner_radius(egui::CornerRadius::same(6))
        .min_size(egui::vec2(120.0, 34.0)),
    )
}

fn secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .color(tokiwa())
                .strong()
                .size(14.0),
        )
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, tokiwa()))
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
    // Ignore an empty PROMPT_PAROLE_HOME (it would otherwise yield a relative,
    // broken data dir); fall through to ~/.prompt-parole.
    if let Ok(value) = env::var("PROMPT_PAROLE_HOME")
        && !value.trim().is_empty()
    {
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
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, tokiwa());
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, sumi());
    visuals.window_stroke = egui::Stroke::new(1.0, line());
    style.visuals = visuals;
    ctx.set_global_style(style);
}

// Every color below is an exact value from nipponcolors.com (a traditional
// Japanese color). Roles are chosen so text always meets WCAG contrast: light
// accents (torinoko/seiji/asagi/yamabuki) carry sumi (dark) text; dark accents
// (tokiwa/enji) carry gofun (white) text.

/// Shironeri 白練 — warm off-white. Page background and inset fields.
fn shironeri() -> egui::Color32 {
    egui::Color32::from_rgb(252, 250, 242)
}

/// Gofun 胡粉 — shell white. Cards/panels and text on dark fills.
fn gofun() -> egui::Color32 {
    egui::Color32::from_rgb(255, 255, 251)
}

/// Torinoko 鳥の子 — pale beige. Alerts and hover backgrounds.
fn torinoko() -> egui::Color32 {
    egui::Color32::from_rgb(218, 201, 166)
}

/// Seiji 青磁 — celadon. Pressed-widget background.
fn seiji() -> egui::Color32 {
    egui::Color32::from_rgb(105, 176, 172)
}

/// Tokiwa 常磐色 — deep evergreen. Primary actions/accents (readable as both a
/// fill with white text and as text on white, unlike the brighter Aomidori).
fn tokiwa() -> egui::Color32 {
    egui::Color32::from_rgb(0, 123, 67)
}

/// Asagi 浅葱 — light indigo. Selection highlight and the busy indicator.
fn asagi() -> egui::Color32 {
    egui::Color32::from_rgb(51, 166, 184)
}

/// Yamabuki 山吹 — golden. "Not configured" state.
fn yamabuki() -> egui::Color32 {
    egui::Color32::from_rgb(255, 177, 27)
}

/// Enji 臙脂 — dark crimson. Errors and the "blocked" state.
fn enji() -> egui::Color32 {
    egui::Color32::from_rgb(159, 53, 58)
}

/// Sumi 墨 — ink black. Primary text.
fn sumi() -> egui::Color32 {
    egui::Color32::from_rgb(28, 28, 28)
}

/// Nibi 鈍 — dull dark grey. Secondary/meta text (passes WCAG AA on the panels,
/// unlike the lighter Rikyū-nezumi).
fn nibi() -> egui::Color32 {
    egui::Color32::from_rgb(101, 103, 101)
}

fn panel() -> egui::Color32 {
    gofun()
}

fn field() -> egui::Color32 {
    shironeri()
}

/// Hairline rule: Sumi at low opacity.
fn line() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(28, 28, 28, 46)
}

fn button_fg() -> egui::Color32 {
    gofun()
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
        #[arg(long)]
        password_stdin: bool,
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
    /// Gate the Claude Code and Codex VS Code extensions during curfew.
    InstallVscode {
        #[arg(long)]
        password_stdin: bool,
    },
    UninstallVscode {
        #[arg(long)]
        password_stdin: bool,
    },
    Launch {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        real: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
    #[command(hide = true)]
    Proxy {
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
            // Fail on an already-configured machine or bad arguments BEFORE asking
            // for a password, so the user does not type one only to be rejected.
            if core.is_configured() {
                return Err(
                    "Prompt Parole is already configured. Use passwd to change the password."
                        .to_owned(),
                );
            }
            let actions = action_list(password_required_for);
            config_from_parts(
                lock_window.clone(),
                timezone.clone(),
                unlock_duration_minutes,
                actions.clone(),
            )?;
            let (first, second) = read_new_password(password_stdin)?;
            if first != second {
                return Err("Passwords do not match.".to_owned());
            }
            core.setup(
                &first,
                lock_window,
                timezone,
                unlock_duration_minutes,
                actions,
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
            let timezone = timezone.unwrap_or(existing.timezone);
            let unlock_duration_minutes =
                unlock_duration_minutes.unwrap_or(existing.unlock_duration_minutes);
            let actions = password_required_for
                .map(|value| action_list(Some(value)))
                .unwrap_or(existing.password_required_for);
            // Validate the merged config before prompting for the password.
            config_from_parts(
                windows.clone(),
                timezone.clone(),
                unlock_duration_minutes,
                actions.clone(),
            )?;
            let current = read_current_password(password_stdin, "Current password: ")?;
            let config = core.configure(
                &current,
                windows,
                timezone,
                unlock_duration_minutes,
                actions,
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
            // Resolve the duration (which may read config) BEFORE prompting, so a
            // config error doesn't waste the user's password entry.
            let minutes = match duration_minutes {
                Some(value) => value,
                None => core.load_config()?.unlock_duration_minutes,
            };
            let password = read_current_password(password_stdin, "Password: ")?;
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
            // Unconfigured = allow (exit 0). A genuine status/config-load error must NOT
            // silently allow: it propagates as Err -> exit 2, and the launcher wrappers
            // treat any non-zero exit as "block", so a corrupt config fails CLOSED like
            // every other enforcement path (hook, guard, launch).
            if !core.is_configured() {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"allowed": true, "reason": "Prompt Parole is not configured."})
                    );
                } else {
                    println!("allowed");
                }
                return Ok(0);
            }
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
        CommandKind::GuardAgent {
            action,
            password_stdin,
        } => {
            match action {
                GuardAgentAction::Start => {
                    start_guard_agent(core)?;
                    println!("Input guard agent started.");
                }
                GuardAgentAction::Stop => {
                    // Stopping the guard removes an enforcement layer, so gate it
                    // like unlock/uninstall (the "disable" action).
                    require_action_password(core, password_stdin, "disable")?;
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
                    .map(|command| ensure_hook_marker(&command))
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
        CommandKind::InstallVscode { password_stdin } => {
            require_action_password(core, password_stdin, "install")?;
            println!("{}", install_vscode_wrappers(core)?);
            Ok(0)
        }
        CommandKind::UninstallVscode { password_stdin } => {
            require_action_password(core, password_stdin, "uninstall")?;
            println!("{}", uninstall_vscode_wrappers(core)?);
            Ok(0)
        }
        CommandKind::Launch { agent, real, args } => launch_agent(core, &agent, &real, &args),
        CommandKind::Proxy { agent, real, args } => proxy_agent(core, &agent, &real, &args),
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
    let mut targets: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let clean = part.trim().to_lowercase();
        if clean.is_empty() {
            continue;
        }
        if clean != "claude" && clean != "codex" {
            return Err(format!(
                "Unknown target {clean:?}; expected claude or codex."
            ));
        }
        // Dedup so repeated targets do not double-process the same config (and so
        // a second pass cannot trip over the first pass's own changes).
        if !targets.contains(&clean) {
            targets.push(clean);
        }
    }
    if targets.is_empty() {
        return Err("At least one target is required.".to_owned());
    }
    Ok(targets)
}

/// Whether a curfew is currently active (slow-changing; refreshed by the guard's
/// poll thread). The focused-window check is done live in the event-tap callback,
/// so this only needs minute-granularity accuracy.
static CURFEW_ACTIVE: AtomicBool = AtomicBool::new(false);

/// PID of the focused window the poll thread last confirmed runs an agent via its
/// process tree (0 = none). The event-tap callback consults this for the
/// title-less-terminal fallback instead of spawning `ps` itself.
static FOCUS_TARGET_PID: AtomicI32 = AtomicI32::new(0);

const GUARD_FLAG_CONTROL: u64 = 1 << 18;
const GUARD_FLAG_OPTION: u64 = 1 << 19;
const GUARD_FLAG_COMMAND: u64 = 1 << 20;
const GUARD_KEY_V: i64 = 9;
const GUARD_KEY_J: i64 = 38;
const GUARD_KEY_M: i64 = 46;
const GUARD_KEY_RETURN: i64 = 36;
const GUARD_KEY_ENTER: i64 = 76;

// ponytail: keyboard-only guard. A keyboard event tap cannot see mouse "Edit >
// Paste", drag-and-drop text, or Dictation, so those remain possible during
// curfew. This matches the documented threat model (stop a habit, not defeat the
// machine owner); closing them would require an accessibility/pasteboard observer.
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

fn guard_curfew_active(core: &ParoleCore) -> bool {
    // Fail CLOSED: if configured but the decision can't be computed (e.g. unreadable
    // config), treat the curfew as active — the same safe re-lock direction
    // load_state() takes on corruption.
    core.is_configured()
        && core
            .decision()
            .map(|decision| !decision.allowed)
            .unwrap_or(true)
}

fn run_input_guard(core: ParoleCore, poll_millis: u64) -> Result<i32, String> {
    if poll_millis < 50 {
        return Err("poll-millis must be at least 50.".to_owned());
    }
    println!("Prompt Parole input guard is running.");
    println!("Output remains visible; keyboard input to locked Codex/Claude windows is blocked.");
    // The poll thread tracks the (slow-changing) curfew state AND the process-tree
    // fallback (which spawns `ps`, so it must NOT run inside the event-tap callback).
    // The callback re-checks the focused window's title live, so a focus switch can't
    // slip a prompt through on the common (title-bearing) path.
    CURFEW_ACTIVE.store(guard_curfew_active(&core), Ordering::Relaxed);
    FOCUS_TARGET_PID.store(focus_target_pid(), Ordering::Relaxed);
    let poll_core = core.clone();
    thread::spawn(move || {
        loop {
            CURFEW_ACTIVE.store(guard_curfew_active(&poll_core), Ordering::Relaxed);
            FOCUS_TARGET_PID.store(focus_target_pid(), Ordering::Relaxed);
            thread::sleep(StdDuration::from_millis(poll_millis));
        }
    });
    platform_run_input_guard()
}

/// PID of the focused window if it is a terminal emulator whose process tree runs
/// an agent (else 0). Runs in the poll thread (spawns `ps`), never in the callback.
#[cfg(target_os = "macos")]
fn focus_target_pid() -> i32 {
    macos_front_window::frontmost_window()
        .filter(|window| {
            is_terminal_owner(&window.owner) && window.pid > 0 && pid_tree_runs_agent(window.pid)
        })
        .map(|window| window.pid)
        .unwrap_or(0)
}

#[cfg(not(target_os = "macos"))]
fn focus_target_pid() -> i32 {
    0
}

/// True if the focused window is a Codex/Claude prompt target. Called live in the
/// event-tap callback: a fast title/owner check (no `ps`), plus the cheap
/// process-tree result the poll thread precomputed for this PID.
#[cfg(target_os = "macos")]
fn current_window_is_target() -> bool {
    let Some(window) = macos_front_window::frontmost_window() else {
        return false;
    };
    if window_is_agent_target(&window.owner, &window.title) {
        return true;
    }
    // Process-tree fallback for terminals whose title does NOT surface the agent.
    // A terminal emulator shares ONE owner pid across all its windows/tabs, and there
    // is no reliable window/tab -> child-process mapping, so this can also block a
    // sibling shell window of the same app during curfew. That over-block is the
    // deliberate fail-SAFE direction: narrowing it (e.g. by window number) would risk
    // letting an agent prompt through during a focus switch, which defeats the curfew.
    let tree_pid = FOCUS_TARGET_PID.load(Ordering::Relaxed);
    window.pid > 0 && window.pid == tree_pid
}

#[cfg(target_os = "macos")]
fn window_info_is_target(window: &macos_front_window::WindowInfo) -> bool {
    if window_is_agent_target(&window.owner, &window.title) {
        return true;
    }
    // Process-tree fallback ONLY for terminal emulators, where the whole window is
    // the terminal. We deliberately do NOT apply it to editors/IDEs (e.g. VS Code):
    // there the agent runs in an embedded terminal but blocking the window would
    // also block the editor, breaking the "you can still read/edit" promise.
    is_terminal_owner(&window.owner) && window.pid > 0 && pid_tree_runs_agent(window.pid)
}

#[cfg(target_os = "macos")]
fn is_terminal_owner(owner: &str) -> bool {
    TERMINAL_OWNERS.contains(&owner.to_ascii_lowercase().as_str())
}

/// Whether `pid` or any descendant is a Codex/Claude process. The full process
/// snapshot is cached briefly so the per-keystroke live check does not spawn `ps`
/// on every key.
/// (pid, ppid, executable-path) rows from `ps`.
#[cfg(target_os = "macos")]
type ProcRows = Vec<(i32, i32, String)>;

#[cfg(target_os = "macos")]
fn pid_tree_runs_agent(pid: i32) -> bool {
    static CACHE: Mutex<Option<(Instant, ProcRows)>> = Mutex::new(None);
    let mut guard = match CACHE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let stale = guard
        .as_ref()
        .map(|(stamp, _)| stamp.elapsed() >= StdDuration::from_millis(300))
        .unwrap_or(true);
    if stale {
        *guard = Some((Instant::now(), read_process_rows()));
    }
    guard
        .as_ref()
        .map(|(_, rows)| tree_has_agent(rows, pid))
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn read_process_rows() -> Vec<(i32, i32, String)> {
    let Ok(output) = Command::new("ps")
        .args(["-axww", "-o", "pid=,ppid=,comm="])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_proc_row)
        .collect()
}

#[cfg(target_os = "macos")]
fn parse_proc_row(line: &str) -> Option<(i32, i32, String)> {
    // `ps` pads columns with runs of spaces. split_whitespace() collapses those so
    // the numeric fields parse; the comm path (which may contain spaces) is then
    // recovered as the positional remainder after the first two fields.
    let trimmed = line.trim_start();
    let mut fields = trimmed.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    let ppid = fields.next()?.parse().ok()?;
    let after_pid = trimmed
        .trim_start_matches(|c: char| !c.is_whitespace())
        .trim_start();
    let comm = after_pid
        .trim_start_matches(|c: char| !c.is_whitespace())
        .trim_start()
        .to_owned();
    if comm.is_empty() {
        return None;
    }
    Some((pid, ppid, comm))
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
        // Try the keyboard guard, but don't let a missing Accessibility permission
        // abort the watchdog: the watchdog needs no permission and retries the
        // keyboard guard once permission is granted.
        let keyboard = if input_guard_running() {
            Ok(())
        } else {
            start_guard_once(core)
        };
        start_guard_watchdog_agent(core)?;
        keyboard
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = core;
        Err("Input Guard agent is currently implemented only for macOS.".to_owned())
    }
}

#[cfg(target_os = "macos")]
fn start_guard_once(core: &ParoleCore) -> Result<(), String> {
    // Run the guard headlessly via launchd. We never open a Terminal window: if the
    // event tap can't be created it's almost always a missing permission, and a
    // surprise Terminal is worse than a clear instruction to grant it.
    let plist = guard_agent_plist_path()?;
    write_guard_agent_plist(core, &plist)?;
    let domain = launchctl_domain()?;
    let target = launchctl_target(&domain, GUARD_AGENT_LABEL);
    reload_launch_agent(&domain, &target, &plist)?;
    run_launchctl(&["kickstart", "-k", &target])?;
    thread::sleep(StdDuration::from_millis(900));
    if input_guard_running() {
        Ok(())
    } else {
        // Tear the agent back down so launchd does not respawn a permission-less
        // guard every ~10s (KeepAlive) until the user grants permission.
        let _ = run_launchctl(&["bootout", &target]);
        Err(
            "Input guard did not stay running. Grant Prompt Parole permission under \
             System Settings > Privacy & Security > Input Monitoring (and Accessibility), \
             then start it again."
                .to_owned(),
        )
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
    reload_launch_agent(&domain, &target, &plist)?;
    run_launchctl(&["kickstart", "-k", &target])?;
    thread::sleep(StdDuration::from_millis(600));
    if guard_watchdog_running() {
        Ok(())
    } else {
        Err("Input guard watchdog did not stay running.".to_owned())
    }
}

/// Re-load a LaunchAgent. `bootout` is asynchronous, so an immediate `bootstrap`
/// can fail with "service already loaded"; wait briefly and retry once.
#[cfg(target_os = "macos")]
fn reload_launch_agent(domain: &str, target: &str, plist: &Path) -> Result<(), String> {
    let plist = plist.to_string_lossy();
    let _ = run_launchctl(&["bootout", target]);
    thread::sleep(StdDuration::from_millis(200));
    if let Err(err) = run_launchctl(&["bootstrap", domain, plist.as_ref()]) {
        thread::sleep(StdDuration::from_millis(400));
        let _ = run_launchctl(&["bootout", target]);
        thread::sleep(StdDuration::from_millis(200));
        return run_launchctl(&["bootstrap", domain, plist.as_ref()]).map_err(|_| err);
    }
    Ok(())
}

fn guard_watchdog_running() -> bool {
    !prompt_parole_process_pids("guard-watchdog").is_empty()
}

const WATCHDOG_MAX_ATTEMPTS: u32 = 3;
const WATCHDOG_RETRY_ATTEMPTS_AFTER_BACKOFF: u32 = 1;
const WATCHDOG_BACKOFF: StdDuration = StdDuration::from_secs(300);
const WATCHDOG_BACKOFF_POLL: StdDuration = StdDuration::from_secs(60);

fn watchdog_backoff_sleep(now: Instant, until: Instant) -> StdDuration {
    until
        .checked_duration_since(now)
        .unwrap_or_default()
        .min(WATCHDOG_BACKOFF_POLL)
}

fn watchdog_attempt_limit(already_backed_off: bool) -> u32 {
    if already_backed_off {
        WATCHDOG_RETRY_ATTEMPTS_AFTER_BACKOFF
    } else {
        WATCHDOG_MAX_ATTEMPTS
    }
}

fn run_guard_watchdog(core: ParoleCore, interval_seconds: u64) -> Result<i32, String> {
    if interval_seconds == 0 {
        return Err("interval-seconds must be positive.".to_owned());
    }
    println!("Prompt Parole guard watchdog is running.");
    let interval = StdDuration::from_secs(interval_seconds);
    let mut failures: u32 = 0;
    let mut backoff_until: Option<Instant> = None;
    let mut already_backed_off = false;
    loop {
        let locked = guard_curfew_active(&core);
        // Only try to (re)start the keyboard event-tap guard if the user actually
        // set it up; VS-Code-only users never started it, so don't churn on it.
        let keyboard_guard_enabled = guard_agent_plist_path()
            .map(|path| path.exists())
            .unwrap_or(false);
        if !locked || !keyboard_guard_enabled {
            // Nothing to recover; reset the backoff state.
            failures = 0;
            backoff_until = None;
            already_backed_off = false;
            thread::sleep(interval);
            continue;
        }

        if let Some(until) = backoff_until {
            let now = Instant::now();
            if now < until {
                thread::sleep(watchdog_backoff_sleep(now, until));
                continue;
            }
            backoff_until = None;
        }

        if !input_guard_running() {
            match recover_guard_from_watchdog(&core) {
                Ok(()) => {
                    failures = 0;
                    backoff_until = None;
                    already_backed_off = false;
                }
                Err(err) => {
                    failures += 1;
                    let attempt_limit = watchdog_attempt_limit(already_backed_off);
                    eprintln!(
                        "prompt-parole watchdog: could not start input guard (attempt {failures}): {err}"
                    );
                    // Stop opening recovery windows on a loop when the guard
                    // cannot stay up (usually missing Accessibility/Input
                    // Monitoring permission); back off and try again later.
                    if failures >= attempt_limit {
                        eprintln!(
                            "prompt-parole watchdog: backing off for {} minutes. Grant Accessibility/Input Monitoring permission to prompt-parole, then it will retry.",
                            WATCHDOG_BACKOFF.as_secs() / 60
                        );
                        backoff_until = Some(Instant::now() + WATCHDOG_BACKOFF);
                        failures = 0;
                        already_backed_off = true;
                    }
                }
            }
        } else {
            // Guard is healthy.
            failures = 0;
            backoff_until = None;
            already_backed_off = false;
        }
        thread::sleep(interval);
    }
}

// Recover by re-launching the headless launchd guard — never a Terminal window.
fn recover_guard_from_watchdog(core: &ParoleCore) -> Result<(), String> {
    start_guard_once(core)
}

/// Open the macOS Input Monitoring privacy pane so the user can grant permission.
fn open_input_monitoring_settings() {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent")
            .status();
    }
}

fn stop_guard_agent(core: &ParoleCore) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let domain = launchctl_domain()?;
        let guard_target = launchctl_target(&domain, GUARD_AGENT_LABEL);
        let watchdog_target = launchctl_target(&domain, GUARD_WATCHDOG_LABEL);
        // Fully tear down the watchdog FIRST — unload its plist AND kill its process,
        // then wait until it is actually gone — before booting out the guard. Both
        // bootout and kill are asynchronous, so without the wait a still-running
        // watchdog could re-bootstrap the KeepAlive guard right after we stop it.
        let watchdog_result = stop_launchctl_target(&watchdog_target);
        stop_guard_watchdog_processes();
        let deadline = Instant::now() + StdDuration::from_secs(3);
        while guard_watchdog_running() && Instant::now() < deadline {
            thread::sleep(StdDuration::from_millis(100));
        }
        let guard_result = stop_launchctl_target(&guard_target);
        stop_guard_processes();
        // Legacy cleanup: older builds could pause VS Code agents, so stopping
        // the guard should never leave those processes frozen.
        resume_vscode_agents(core);
        watchdog_result.and(guard_result)
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
    // Read the executable path (comm) and full command line (args) separately so a
    // bundle path containing a space (".../Prompt Parole.app/.../prompt-parole")
    // is identified by its real basename rather than split mid-path.
    let exes = ps_field_map("comm");
    let args = ps_field_map("args");
    let self_pid = std::process::id();
    exes.into_iter()
        .filter(|(pid, _)| *pid != self_pid)
        .filter_map(|(pid, exe)| {
            let arg_line = args.get(&pid).map(String::as_str).unwrap_or("");
            process_matches(&exe, arg_line, command_arg).then_some(pid)
        })
        .collect()
}

fn ps_field_map(field: &str) -> HashMap<u32, String> {
    let format = format!("pid=,{field}=");
    let mut map = HashMap::new();
    let Ok(output) = Command::new("ps").args(["-axww", "-o", &format]).output() else {
        return map;
    };
    if !output.status.success() {
        return map;
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some((pid, rest)) = split_pid_line(line) {
            map.insert(pid, rest.to_owned());
        }
    }
    map
}

fn split_pid_line(line: &str) -> Option<(u32, &str)> {
    let mut parts = line.trim_start().splitn(2, char::is_whitespace);
    let pid = parts.next()?.parse().ok()?;
    Some((pid, parts.next().unwrap_or("").trim_start()))
}

/// True if `exe_path` (the process's executable) is prompt-parole and its first
/// argument is `command_arg`. Tolerant of spaces in the executable path.
fn process_matches(exe_path: &str, args: &str, command_arg: &str) -> bool {
    let exe_path = exe_path.trim();
    if Path::new(exe_path)
        .file_name()
        .and_then(|name| name.to_str())
        != Some("prompt-parole")
    {
        return false;
    }
    // `args` starts with the executable path; the subcommand is the token after it.
    let subcommand = args
        .trim_start()
        .strip_prefix(exe_path)
        .map(str::trim_start)
        .and_then(|rest| rest.split_whitespace().next())
        .or_else(|| {
            let tokens: Vec<&str> = args.split_whitespace().collect();
            tokens
                .iter()
                .position(|token| {
                    Path::new(token).file_name().and_then(|name| name.to_str())
                        == Some("prompt-parole")
                })
                .and_then(|index| tokens.get(index + 1).copied())
        });
    subcommand == Some(command_arg)
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
        &["guard-watchdog", "--interval-seconds", "5"],
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
    // Propagate a custom data dir to the launchd job, which otherwise would not
    // inherit PROMPT_PAROLE_HOME and would read the wrong (default) config.
    let env_xml = match env::var("PROMPT_PAROLE_HOME") {
        Ok(home) if !home.is_empty() => format!(
            "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>PROMPT_PAROLE_HOME</key>\n    <string>{}</string>\n  </dict>\n",
            xml_escape(&home)
        ),
        _ => String::new(),
    };
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
{env_xml}  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>30</integer>
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
        env_xml = env_xml,
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
        target_focused: window_info_is_target(&window),
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

/// Terminal emulators that title their window with the running command, so a
/// title match is a reliable signal that Codex/Claude is in the foreground.
const TERMINAL_OWNERS: [&str; 9] = [
    "terminal",
    "iterm2",
    "iterm",
    "ghostty",
    "kitty",
    "wezterm",
    "alacritty",
    "hyper",
    "tabby",
];

fn window_is_agent_target(owner: &str, title: &str) -> bool {
    let owner = owner.to_ascii_lowercase();
    let title = title.to_ascii_lowercase();
    if owner.contains("codex") || owner.contains("claude") {
        return true;
    }
    TERMINAL_OWNERS.contains(&owner.as_str())
        && (title.contains("codex") || title.contains("claude"))
}

/// True if a process named like the agent (`claude`/`codex`) is `root` or a
/// descendant of it. Pure over `rows` = (pid, ppid, comm) so it is unit-testable.
fn tree_has_agent(rows: &[(i32, i32, String)], root: i32) -> bool {
    let mut stack = vec![root];
    let mut seen = std::collections::HashSet::new();
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        for (child, parent, comm) in rows {
            if *parent == pid {
                if comm_is_agent(comm) {
                    return true;
                }
                stack.push(*child);
            }
            if *child == pid && comm_is_agent(comm) {
                return true;
            }
        }
    }
    false
}

fn comm_is_agent(comm: &str) -> bool {
    let comm = comm.to_ascii_lowercase();
    comm.contains("claude") || comm.contains("codex")
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
        pub pid: i32,
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        static kCGWindowOwnerName: CfStringRef;
        static kCGWindowOwnerPID: CfStringRef;
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
        fn CFStringGetLength(string: CfStringRef) -> CfIndex;
        fn CFStringGetMaximumSizeForEncoding(length: CfIndex, encoding: u32) -> CfIndex;
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
                let pid = window_int(dict, kCGWindowOwnerPID).unwrap_or(0);
                result = Some(WindowInfo { owner, title, pid });
                break;
            }
            CFRelease(list);
            result
        }
    }

    unsafe fn window_layer(dict: CfDictionaryRef) -> Option<i32> {
        unsafe { window_int(dict, kCGWindowLayer) }
    }

    unsafe fn window_int(dict: CfDictionaryRef, key: CfStringRef) -> Option<i32> {
        let value = unsafe { CFDictionaryGetValue(dict, key) as CfNumberRef };
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
        // Size the buffer to the string's actual UTF-8 length (+1 for NUL) so long
        // window titles are not silently dropped by a fixed-size buffer.
        let length = unsafe { CFStringGetLength(value) };
        if length <= 0 {
            return Some(String::new());
        }
        let max =
            unsafe { CFStringGetMaximumSizeForEncoding(length, K_CF_STRING_ENCODING_UTF8) }.max(0);
        let capacity = (max as usize).saturating_add(1);
        let mut buffer = vec![0_i8; capacity];
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
    use super::{CURFEW_ACTIVE, current_window_is_target, should_block_guard_key};
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicPtr, Ordering};

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
    // macOS delivers these special event types to the callback when it disables
    // the tap (callback too slow, or a burst of user input). We must re-enable it.
    const K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT: u32 = 0xFFFF_FFFE;
    const K_CG_EVENT_TAP_DISABLED_BY_USER_INPUT: u32 = 0xFFFF_FFFF;

    /// The tap's mach port, stored so the callback can re-enable it. The callback's
    /// proxy argument is NOT the port and cannot be passed to CGEventTapEnable.
    static TAP_PORT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

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
        // A panic must not unwind across this `extern "C"` boundary (that aborts the
        // process). Contain it and, if anything goes wrong, pass the event through.
        let block = std::panic::catch_unwind(|| {
            if event_type == K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT
                || event_type == K_CG_EVENT_TAP_DISABLED_BY_USER_INPUT
            {
                // macOS disabled the tap; re-enable it immediately rather than waiting
                // for the run-loop timeout (which would leave the curfew unenforced).
                let port = TAP_PORT.load(Ordering::Acquire);
                if !port.is_null() {
                    unsafe { CGEventTapEnable(port, true) };
                }
                return false;
            }
            if event_type == K_CG_EVENT_KEY_DOWN && CURFEW_ACTIVE.load(Ordering::Relaxed) {
                let key_code =
                    unsafe { CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE) };
                let flags = unsafe { CGEventGetFlags(event) };
                // Only pay for the live focus check on keys we would actually block.
                return should_block_guard_key(key_code, flags) && current_window_is_target();
            }
            false
        })
        .unwrap_or(false);
        if block { ptr::null_mut() } else { event }
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
            TAP_PORT.store(tap, Ordering::Release);
            let source = CFMachPortCreateRunLoopSource(ptr::null(), tap, 0);
            if source.is_null() {
                return Err("Could not create macOS event-tap run loop source.".to_owned());
            }
            let run_loop = CFRunLoopGetCurrent();
            CFRunLoopAddSource(run_loop, source, kCFRunLoopDefaultMode);
            CFRunLoopAddSource(run_loop, source, kCFRunLoopCommonModes);
            CGEventTapEnable(tap, true);
            // The callback re-enables the tap immediately when macOS disables it, so
            // the run loop can block continuously (no per-iteration sleep that would
            // hold keystrokes). The long timeout + re-enable is a cheap backstop.
            loop {
                CGEventTapEnable(tap, true);
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 3600.0, false);
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
        vscode_guarded: {
            let core = ParoleCore { app_dir: app_dir() };
            vscode_wrapper_configured(&core, VSCODE_CLAUDE_SETTING)
                || vscode_wrapper_configured(&core, VSCODE_CODEX_SETTING)
        },
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
    // Use the login shell's PATH, not this process's. A GUI .app launched from
    // Finder inherits a minimal PATH and would otherwise miss ~/.local/bin and
    // wrongly report "Needs install" / "Not first in PATH".
    find_on_path_in(&effective_shell_path(), target)
        .is_some_and(|path| is_prompt_parole_launcher(&path))
}

fn find_on_path_in(paths: &std::ffi::OsStr, target: &str) -> Option<PathBuf> {
    for dir in env::split_paths(paths) {
        let candidate = dir.join(target);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The PATH the user's interactive terminal would see, queried from the login
/// shell once and cached. Falls back to this process's PATH.
fn effective_shell_path() -> std::ffi::OsString {
    static CACHE: OnceLock<std::ffi::OsString> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            if let Some(stdout) = login_shell_path_output()
                && let Some(path) = stdout
                    .lines()
                    .rev()
                    .find_map(|line| line.strip_prefix("PP_PATH="))
                && !path.trim().is_empty()
            {
                return std::ffi::OsString::from(path.trim());
            }
            env::var_os("PATH").unwrap_or_default()
        })
        .clone()
}

/// Run the login shell to print `$PATH`, bounded by a timeout so a slow or hanging
/// shell init cannot wedge the thread that calls this.
fn login_shell_path_output() -> Option<String> {
    use std::process::Stdio;
    let shell = env::var_os("SHELL")?;
    let mut child = Command::new(&shell)
        .args(["-lic", "printf 'PP_PATH=%s\\n' \"$PATH\""])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });
    let result = rx.recv_timeout(StdDuration::from_secs(3)).ok();
    // Reap the shell (kill it if it overran the timeout); the reader thread then
    // sees EOF and exits on its own.
    let _ = child.kill();
    let _ = child.wait();
    result
}

struct LauncherInstallReport {
    wrapper: PathBuf,
    backup: Option<PathBuf>,
}

fn install_launcher(target: &str, bin_dir: Option<&Path>) -> Result<LauncherInstallReport, String> {
    let dir = launcher_bin_dir(bin_dir)?;
    fs::create_dir_all(&dir).map_err(|err| format!("Could not create {}: {err}", dir.display()))?;
    let wrapper = dir.join(target);
    // If a non-launcher entry already occupies the wrapper path, move it aside FIRST.
    // That file is the user's real agent, so the wrapper must then point at the backup
    // (not at the now-vacated wrapper path). Use symlink_metadata so a dangling
    // symlink is also moved aside, rather than being written *through* by fs::write.
    let entry_exists = fs::symlink_metadata(&wrapper).is_ok();
    let backup = if entry_exists && !is_prompt_parole_launcher(&wrapper) {
        let backup = unique_path(&wrapper.with_file_name(format!(
            "{}.prompt-parole.backup.{}",
            target,
            Utc::now().format("%Y%m%d%H%M%S")
        )));
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
    let real = match &backup {
        // The file we just backed up was the real agent (or a symlink to it).
        Some(path) if path.is_file() => path.clone(),
        _ => locate_real_agent_binary(target, &wrapper)?,
    };
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("prompt-parole"));
    write_launcher_script(&wrapper, &exe, target, &real)?;
    Ok(LauncherInstallReport { wrapper, backup })
}

/// Append a numeric suffix until the path does not exist, so same-second backups
/// never overwrite each other.
fn unique_path(base: &Path) -> PathBuf {
    if !base.exists() {
        return base.to_path_buf();
    }
    let name = base
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("backup");
    for suffix in 1..10_000 {
        let candidate = base.with_file_name(format!("{name}.{suffix}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    base.to_path_buf()
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
    // A non-launcher file at the wrapper path is the real agent.
    if wrapper.exists() && !is_prompt_parole_launcher(wrapper) {
        return Ok(wrapper.to_path_buf());
    }

    // Search the login shell's PATH (not this process's — a Finder-launched .app
    // has a minimal PATH), keeping the STABLE path: do NOT canonicalize, which
    // resolves Homebrew/cask symlinks to a version-pinned path that disappears on
    // the next `brew upgrade`.
    let candidates = first_real_agent_candidate(
        env::split_paths(&effective_shell_path())
            .map(|dir| dir.join(target).to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str),
        wrapper,
    );
    if let Some(path) = candidates {
        return Ok(path);
    }

    for path in known_agent_paths(target) {
        if usable_agent_candidate(&path, Some(wrapper)) {
            return Ok(path);
        }
    }

    // Last resort: a previous install backed up the real agent next to the wrapper.
    // Without this, re-installing when the only real binary lives in the backup
    // would fail outright.
    if let Some(dir) = wrapper.parent()
        && let Ok(Some(backup)) = latest_launcher_backup(dir, target)
        && backup.is_file()
    {
        return Ok(backup);
    }

    Err(format!("Could not find the real {target} binary."))
}

fn known_agent_paths(target: &str) -> Vec<PathBuf> {
    ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
        .iter()
        .map(|dir| PathBuf::from(dir).join(target))
        .collect()
}

/// Resolve the real agent binary at launch time, skipping Prompt Parole launchers.
/// Lets an already-installed wrapper survive an agent upgrade that moved/renamed
/// the binary the wrapper was built against.
fn resolve_agent_at_runtime(target: &str) -> Option<PathBuf> {
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join(target);
            if usable_agent_candidate(&candidate, None) {
                return Some(candidate);
            }
        }
    }
    known_agent_paths(target)
        .into_iter()
        .find(|path| usable_agent_candidate(path, None))
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
        usable_agent_candidate(&path, Some(wrapper)).then_some(path)
    })
}

fn usable_agent_candidate(path: &Path, wrapper: Option<&Path>) -> bool {
    if wrapper.is_some_and(|wrapper| path == wrapper) {
        return false;
    }
    path.is_file() && !is_prompt_parole_launcher(path)
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
    // Only "same file" if BOTH paths canonicalize successfully and match. Two
    // canonicalize failures (e.g. bundled_exe doesn't exist yet on first install)
    // must NOT be treated as equal, or the copy would be skipped and the bundle
    // would have no executable.
    let same_file = match (fs::canonicalize(&exe), fs::canonicalize(&bundled_exe)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same_file {
        // Copy to a temp file and rename into place (a fresh inode) rather than
        // overwriting the running binary's inode. Overwriting in place invalidates
        // the kernel's cached code signature and the next launch is SIGKILLed
        // ("Killed: 9") on Apple Silicon.
        let staging = macos.join("prompt-parole.new");
        let _ = fs::remove_file(&staging);
        fs::copy(&exe, &staging).map_err(|err| {
            format!(
                "Could not copy {} to {}: {err}",
                exe.display(),
                staging.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).map_err(|err| {
                let _ = fs::remove_file(&staging);
                format!("Could not make {} executable: {err}", staging.display())
            })?;
        }
        fs::rename(&staging, &bundled_exe).map_err(|err| {
            let _ = fs::remove_file(&staging);
            format!("Could not install {}: {err}", bundled_exe.display())
        })?;
        // Re-establish a valid ad-hoc signature for the freshly written bytes, so
        // the binary is not killed for a signature mismatch.
        adhoc_codesign(&bundled_exe)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bundled_exe, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("Could not make {} executable: {err}", bundled_exe.display()))?;
    }

    install_app_icon(&resources)?;
    fs::write(contents.join("Info.plist"), macos_app_info_plist())
        .map_err(|err| format!("Could not write Info.plist: {err}"))?;
    fs::write(contents.join("PkgInfo"), "APPL????\n")
        .map_err(|err| format!("Could not write PkgInfo: {err}"))?;
    Ok(app)
}

/// Render the icon at every macOS iconset resolution and build Resources/AppIcon.icns.
#[cfg(target_os = "macos")]
fn install_app_icon(resources: &Path) -> Result<(), String> {
    let iconset = resources.join("AppIcon.iconset");
    let _ = fs::remove_dir_all(&iconset);
    fs::create_dir_all(&iconset)
        .map_err(|err| format!("Could not create {}: {err}", iconset.display()))?;
    // (filename, pixel size) for the standard macOS iconset.
    const ENTRIES: [(&str, u32); 10] = [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024),
    ];
    let icns = resources.join("AppIcon.icns");
    // Render + pack inside a closure so the staging iconset is removed on EVERY exit
    // path, including a write_icon_png error or an iconutil spawn failure.
    let render = (|| -> Result<std::process::Output, String> {
        for (name, size) in ENTRIES {
            write_icon_png(&iconset.join(name), size)?;
        }
        Command::new("iconutil")
            .args(["-c", "icns"])
            .arg(&iconset)
            .arg("-o")
            .arg(&icns)
            .output()
            .map_err(|err| format!("Could not run iconutil: {err}"))
    })();
    let _ = fs::remove_dir_all(&iconset);
    let output = render?;
    if !output.status.success() {
        return Err(format!(
            "iconutil failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_icon_png(path: &Path, size: u32) -> Result<(), String> {
    let rgba = render_icon(size);
    let image = image::RgbaImage::from_raw(size, size, rgba)
        .ok_or_else(|| "icon buffer size mismatch".to_owned())?;
    image
        .save_with_format(path, image::ImageFormat::Png)
        .map_err(|err| format!("Could not write {}: {err}", path.display()))
}

/// Ad-hoc re-sign a Mach-O so it is not SIGKILLed for an invalid signature.
#[cfg(target_os = "macos")]
fn adhoc_codesign(path: &Path) -> Result<(), String> {
    let output = Command::new("codesign")
        .args(["--force", "--sign", "-"])
        .arg(path)
        .output()
        .map_err(|err| format!("Could not run codesign: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "codesign failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
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
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
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
    // The baked `--real` path can disappear when the agent is upgraded (e.g. a
    // Homebrew cask version bump). Re-resolve on PATH so the wrapper keeps working.
    let resolved;
    let real = if real.is_file() {
        real
    } else {
        resolved = resolve_agent_at_runtime(agent).ok_or_else(|| {
            format!(
                "Could not find the {agent} binary (it may have been upgraded or removed). \
                 Reinstall the Prompt Parole launcher to repair it."
            )
        })?;
        resolved.as_path()
    };
    let launch_args = launch_args_for_agent(agent, args);
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        run_agent_pty_proxy(core, agent, real, &launch_args)
    } else {
        run_agent_direct(real, &launch_args)
    }
}

fn launch_args_for_agent(agent: &str, args: &[String]) -> Vec<String> {
    let mut launch_args = Vec::new();
    if agent == "codex"
        && !args
            .iter()
            .any(|arg| arg == "--dangerously-bypass-hook-trust")
    {
        launch_args.push("--dangerously-bypass-hook-trust".to_owned());
    }
    launch_args.extend(args.iter().cloned());
    launch_args
}

fn run_agent_direct(real: &Path, args: &[String]) -> Result<i32, String> {
    let status = Command::new(real)
        .args(args)
        .status()
        .map_err(|err| format!("Could not launch {}: {err}", real.display()))?;
    // Report a signal death as 128+signal (POSIX shell convention) so callers can
    // distinguish a crash from an ordinary exit(1).
    Ok(status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map(|sig| 128 + sig).unwrap_or(1)
        }
        #[cfg(not(unix))]
        {
            1
        }
    }))
}

#[cfg(unix)]
fn run_agent_pty_proxy(
    core: &ParoleCore,
    agent: &str,
    real: &Path,
    args: &[String],
) -> Result<i32, String> {
    use portable_pty::{CommandBuilder, native_pty_system};

    let _raw_mode = RawTerminalMode::enter_stdin().map_err(|err| {
        format!(
            "Could not prepare protected terminal input for {agent}: {err}. \
             Prompt Parole will not start an unprotected interactive session."
        )
    })?;

    // portable-pty and std assume fd 1 is blocking; some parents (e.g. Node) leave
    // O_NONBLOCK set on an inherited tty, which would make write_all_stdout_raw spin
    // at 100% CPU on EAGAIN. Restore the blocking invariant once, best-effort.
    unsafe {
        let flags = libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL);
        if flags != -1 && (flags & libc::O_NONBLOCK) != 0 {
            libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(current_pty_size())
        .map_err(|err| format!("Could not create protected terminal for {agent}: {err}"))?;
    let mut cmd = CommandBuilder::new(real.as_os_str());
    cmd.args(args.iter().map(String::as_str));
    // portable-pty defaults the child's working directory to $HOME when cwd is
    // unset (CommandBuilder::as_command -> get_home_dir), so without this every
    // proxied agent would start in the home dir instead of where it was launched.
    // This must hold regardless of curfew; curfew only gates stdin, below.
    if let Ok(cwd) = std::env::current_dir() {
        cmd.cwd(cwd);
    }
    let mut child = pair.slave.spawn_command(cmd).map_err(|err| {
        format!(
            "Could not launch {} in protected terminal: {err}",
            real.display()
        )
    })?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|err| format!("Could not read protected terminal output: {err}"))?;
    let mut writer = pair
        .master
        .take_writer()
        .map_err(|err| format!("Could not write protected terminal input: {err}"))?;

    // Capture the agent pid before spawning the pumps: the output thread uses it to
    // hang up a child that would otherwise block on a full PTY buffer, and we reap it
    // ourselves below to recover the real exit/signal code.
    let child_pid = child.process_id();

    let done = Arc::new(AtomicBool::new(false));
    // Set when the output pump actually exits, so shutdown can flush every byte (join)
    // in the common case yet detach (never hang) if a grandchild holds the slave open.
    let output_finished = Arc::new(AtomicBool::new(false));
    let output_done = Arc::clone(&done);
    let output_finished_flag = Arc::clone(&output_finished);
    let output_thread = thread::spawn(move || {
        // Pump child output straight to fd 1, byte for byte. Do NOT route this through
        // std::io::stdout(): that is a LineWriter, so it withholds every byte after the
        // last '\n' until a newline arrives or its ~1KB buffer fills. TUI agents
        // (claude/codex) redraw with newline-free escape sequences and echo keystrokes
        // the same way, so a line buffer makes typed characters and screen updates
        // appear seconds late. A PTY proxy must be byte-transparent in both directions.
        let mut buf = [0_u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => {
                    if write_all_stdout_raw(&buf[..read]).is_err() {
                        // fd 1 is gone; nothing will drain the PTY, so a child that
                        // fills the kernel buffer would block forever. Hang up the
                        // agent so its wait() can return.
                        if let Some(pid) = child_pid {
                            unsafe {
                                libc::kill(pid as i32, libc::SIGHUP);
                            }
                        }
                        break;
                    }
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // Let the input/resize threads stop spinning even if the agent outlives fd 1,
        // and signal the shutdown path that all output has been drained.
        output_done.store(true, Ordering::Relaxed);
        output_finished_flag.store(true, Ordering::Relaxed);
    });

    let resize_done = Arc::clone(&done);
    let master = pair.master;
    let resize_thread = thread::spawn(move || {
        let mut last_size = current_pty_size();
        let _ = master.resize(last_size);
        while !resize_done.load(Ordering::Relaxed) {
            thread::sleep(StdDuration::from_millis(250));
            let next_size = current_pty_size();
            if next_size != last_size {
                let _ = master.resize(next_size);
                last_size = next_size;
            }
        }
    });

    let input_core = core.clone();
    let input_done = Arc::clone(&done);
    let input_thread = thread::spawn(move || {
        let mut stderr = std::io::stderr().lock();
        let mut buf = [0_u8; 4096];
        let mut warned_locked = false;
        loop {
            if input_done.load(Ordering::Relaxed) {
                break;
            }
            let read = match poll_stdin_chunk(&mut buf, 100) {
                Ok(Some(read)) => read,
                Ok(None) => continue,
                Err(_) => break,
            };
            if read == 0 {
                break;
            }
            if guard_curfew_active(&input_core) {
                if !warned_locked {
                    let _ = stderr.write_all(
                        b"\r\nPrompt Parole: curfew is active; terminal agent input is blocked while output remains visible.\r\n",
                    );
                    let _ = stderr.flush();
                    warned_locked = true;
                }
                continue;
            }
            warned_locked = false;
            if writer.write_all(&buf[..read]).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    // Reap the agent ourselves so a signal death reports the POSIX 128+signal code
    // instead of portable-pty's lossy collapse to exit code 1. std::process::Child
    // (what spawn_command returns) has a no-op Drop, so reaping its pid directly is
    // safe and never double-waits.
    let mut reaped: Option<i32> = None;
    if let Some(pid) = child_pid {
        let mut raw: libc::c_int = 0;
        loop {
            let r = unsafe { libc::waitpid(pid as i32, &mut raw, 0) };
            if r == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break; // ECHILD/other: fall back to portable-pty's wait below.
            }
            if libc::WIFEXITED(raw) {
                reaped = Some(libc::WEXITSTATUS(raw));
                break;
            }
            if libc::WIFSIGNALED(raw) {
                reaped = Some(128 + libc::WTERMSIG(raw));
                break;
            }
            // Stopped/continued: keep waiting for a terminal state.
        }
    }
    let code = match reaped {
        Some(code) => code,
        // No pid, or waitpid failed: fall back to portable-pty's wait (which loses the
        // numeric signal, collapsing it to exit code 1).
        None => {
            let status = child
                .wait()
                .map_err(|err| format!("Could not wait for {}: {err}", real.display()))?;
            status.exit_code().min(i32::MAX as u32) as i32
        }
    };

    done.store(true, Ordering::Relaxed);
    let _ = input_thread.join();
    let _ = resize_thread.join();
    // Flush remaining output. In the common case the master hits EOF right after the
    // agent closes the slave, so output_finished flips within milliseconds and we join
    // to write every last byte. If a detached grandchild (MCP/language server, node,
    // ripgrep) keeps the slave open, the master never EOFs; after a short grace we
    // DETACH instead of joining, so the terminal is never left hung in raw mode.
    let grace = std::time::Instant::now();
    while !output_finished.load(Ordering::Relaxed)
        && grace.elapsed() < StdDuration::from_millis(1000)
    {
        thread::sleep(StdDuration::from_millis(5));
    }
    if output_finished.load(Ordering::Relaxed) {
        let _ = output_thread.join();
    } else {
        // Detached; the blocked reader is reaped when the process exits a moment later.
        drop(output_thread);
    }
    Ok(code)
}

#[cfg(unix)]
fn poll_stdin_chunk(buf: &mut [u8], timeout_millis: i32) -> Result<Option<usize>, std::io::Error> {
    let mut poll_fd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: `poll_fd` points to one valid pollfd and the timeout is bounded.
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_millis) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if ready == 0 {
            return Ok(None);
        }
        if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Ok(Some(0));
        }
        if poll_fd.revents & libc::POLLIN == 0 {
            return Ok(None);
        }
        // SAFETY: `buf` is valid writable storage for `buf.len()` bytes.
        let read = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if read < 0 {
            let err = std::io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EINTR) | Some(libc::EAGAIN)) {
                return Ok(None);
            }
            return Err(err);
        }
        return Ok(Some(read as usize));
    }
}

#[cfg(unix)]
fn write_all_stdout_raw(mut bytes: &[u8]) -> Result<(), std::io::Error> {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is a valid readable slice of `bytes.len()` bytes.
        let written = unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                bytes.as_ptr().cast::<libc::c_void>(),
                bytes.len(),
            )
        };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // Interrupted before any byte moved: retry immediately.
                Some(libc::EINTR) => continue,
                // fd 1 is non-blocking (an inherited O_NONBLOCK we could not clear):
                // wait for it to become writable instead of spinning on EAGAIN.
                Some(libc::EAGAIN) => {
                    let mut poll_fd = libc::pollfd {
                        fd: libc::STDOUT_FILENO,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: one valid pollfd; an infinite timeout blocks until drain.
                    unsafe {
                        libc::poll(&mut poll_fd, 1, -1);
                    }
                    continue;
                }
                _ => return Err(err),
            }
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[cfg(not(unix))]
fn run_agent_pty_proxy(
    _core: &ParoleCore,
    _agent: &str,
    real: &Path,
    args: &[String],
) -> Result<i32, String> {
    run_agent_direct(real, args)
}

#[cfg(unix)]
fn current_pty_size() -> portable_pty::PtySize {
    let (cols, rows) = terminal_size::terminal_size()
        .map(|(terminal_size::Width(cols), terminal_size::Height(rows))| (cols, rows))
        .unwrap_or((80, 24));
    portable_pty::PtySize {
        rows: rows.max(1),
        cols: cols.max(1),
        pixel_width: 0,
        pixel_height: 0,
    }
}

#[cfg(unix)]
struct RawTerminalMode {
    fd: libc::c_int,
    original: libc::termios,
}

#[cfg(unix)]
impl RawTerminalMode {
    fn enter_stdin() -> Result<Self, std::io::Error> {
        let fd = libc::STDIN_FILENO;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is stdin and `original` points to writable termios storage.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `tcgetattr` succeeded, so `original` is initialized.
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        // SAFETY: `raw` is an initialized termios value.
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        // SAFETY: `fd` is stdin and `raw` points to a valid termios value.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}

#[cfg(unix)]
impl Drop for RawTerminalMode {
    fn drop(&mut self) {
        // SAFETY: `self.original` was captured from this fd by `tcgetattr`.
        let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

fn proxy_agent(
    core: &ParoleCore,
    agent: &str,
    real: &Path,
    args: &[String],
) -> Result<i32, String> {
    if agent != "codex" && agent != "claude" {
        return Err(format!("Unsupported proxy agent {agent:?}."));
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

    let resolved;
    let real = if real.is_file() {
        real
    } else {
        resolved = resolve_agent_at_runtime(agent).ok_or_else(|| {
            format!(
                "Could not find the {agent} binary (it may have been upgraded or removed). \
                 Reinstall the Prompt Parole VS Code wrapper to repair it."
            )
        })?;
        resolved.as_path()
    };

    let mut child = Command::new(real)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("Could not launch {}: {err}", real.display()))?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| format!("Could not open stdin for {}.", real.display()))?;
    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("Could not open stdout for {}.", real.display()))?;
    let mut child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("Could not open stderr for {}.", real.display()))?;

    let stdout_thread = thread::spawn(move || {
        let mut stdout = std::io::stdout().lock();
        let _ = std::io::copy(&mut child_stdout, &mut stdout);
        let _ = stdout.flush();
    });
    let stderr_thread = thread::spawn(move || {
        let mut stderr = std::io::stderr().lock();
        let _ = std::io::copy(&mut child_stderr, &mut stderr);
        let _ = stderr.flush();
    });

    let input_core = core.clone();
    thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0_u8; 8192];
        let mut warned_locked = false;
        while let Ok(read) = stdin.read(&mut buf) {
            if read == 0 {
                break;
            }
            if guard_curfew_active(&input_core) {
                if !warned_locked {
                    eprintln!(
                        "Prompt Parole: curfew is active; VS Code agent input is blocked while output remains visible."
                    );
                    warned_locked = true;
                }
                continue;
            }
            warned_locked = false;
            if child_stdin.write_all(&buf[..read]).is_err() {
                break;
            }
            let _ = child_stdin.flush();
        }
    });

    let status = child
        .wait()
        .map_err(|err| format!("Could not wait for {}: {err}", real.display()))?;
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
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

/// Ensure a custom hook command carries the Prompt Parole marker, so uninstall and
/// status can recognize (and later remove) it.
fn ensure_hook_marker(command: &str) -> String {
    if command.contains("PROMPT_PAROLE_HOOK=1") || command.contains("prompt-parole hook --agent") {
        command.to_owned()
    } else {
        format!("PROMPT_PAROLE_HOOK=1 {command}")
    }
}

// ---------------------------------------------------------------------------
// VS Code extension coverage.
//
// The Claude Code / Codex VS Code extensions do not fire the settings.json /
// hooks.json prompt-submit hook (an upstream bug), so the hook layer can't gate
// them. Instead we point each extension's "launch the agent process" setting at a
// thin Prompt Parole proxy. The proxy refuses to start a new agent during curfew.
// For sessions that were already open when curfew begins, it keeps stdout/stderr
// flowing but stops forwarding stdin to the child agent, so progress stays visible
// and new prompts do not reach the agent.
// ---------------------------------------------------------------------------

const VSCODE_CLAUDE_SETTING: &str = "claudeCode.claudeProcessWrapper";
const VSCODE_CODEX_SETTING: &str = "chatgpt.cliExecutable";

fn vscode_wrapper_dir(core: &ParoleCore) -> PathBuf {
    core.app_dir.join("vscode")
}

/// User settings file that stores VS Code extension wrapper paths.
fn vscode_user_settings_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "Could not find home directory.".to_owned())?;
    #[cfg(target_os = "macos")]
    let path = home.join("Library/Application Support/Code/User/settings.json");
    #[cfg(not(target_os = "macos"))]
    let path = home.join(".config/Code/User/settings.json");
    Ok(path)
}

/// Body that resolves the real agent and runs it through Prompt Parole's stream
/// proxy. `$@` from Claude Code already starts with the bundled binary; Codex's
/// cliExecutable IS the binary, so we resolve the latest bundled codex and proxy
/// it with the args.
fn vscode_wrapper_script(prompt_parole_exe: &Path, exec_body: &str) -> String {
    // `check` exits 0 only when prompts are allowed (which now includes the
    // unconfigured case). Any non-zero exit blocks: 1 = curfew active, 2 = status/
    // config-load error. Blocking on non-zero makes a corrupt config fail CLOSED,
    // matching the hook/guard/launch paths instead of silently allowing new sessions.
    format!(
        "#!/bin/sh\n# PROMPT_PAROLE_LAUNCHER=1\n# Managed by Prompt Parole — gates the VS Code agent during curfew.\n{exe} check >/dev/null 2>&1\nif [ \"$?\" -ne 0 ]; then\n  echo 'Prompt Parole: curfew is active or status is unavailable — new sessions are blocked until your unlock window.' >&2\n  exit 1\nfi\n{body}\n",
        exe = shell_quote(&prompt_parole_exe.to_string_lossy()),
        body = exec_body,
    )
}

fn write_vscode_wrapper(path: &Path, contents: &str) -> Result<(), String> {
    fs::write(path, contents)
        .map_err(|err| format!("Could not write {}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("Could not make {} executable: {err}", path.display()))?;
    }
    Ok(())
}

fn install_vscode_wrappers(core: &ParoleCore) -> Result<String, String> {
    let dir = vscode_wrapper_dir(core);
    ensure_private_dir(&dir)?;
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("prompt-parole"));
    let claude_wrapper = dir.join("vscode-claude-wrapper.sh");
    let codex_wrapper = dir.join("vscode-codex-wrapper.sh");
    let quoted_exe = shell_quote(&exe.to_string_lossy());
    // Claude Code invokes: <wrapper> <bundled-binary> <args...>.
    let claude_body = format!(
        "real=$1\nif [ -z \"$real\" ]; then\n  echo 'Prompt Parole: missing Claude binary.' >&2\n  exit 1\nfi\nshift\nexec {quoted_exe} proxy --agent claude --real \"$real\" -- \"$@\""
    );
    write_vscode_wrapper(&claude_wrapper, &vscode_wrapper_script(&exe, &claude_body))?;
    // Codex (openai.chatgpt) treats cliExecutable AS codex, so resolve the bundled
    // codex (latest version) and proxy it with the args.
    let codex_body = format!(
        "real=$(ls -t \"$HOME\"/.vscode/extensions/openai.chatgpt-*/bin/*/codex 2>/dev/null | head -1)\n[ -n \"$real\" ] || real=codex\nexec {quoted_exe} proxy --agent codex --real \"$real\" -- \"$@\""
    );
    write_vscode_wrapper(&codex_wrapper, &vscode_wrapper_script(&exe, &codex_body))?;

    let settings = vscode_user_settings_path()?;
    let mut data = load_vscode_settings(&settings)?;
    let object = data
        .as_object_mut()
        .ok_or_else(|| "VS Code settings.json must contain a JSON object.".to_owned())?;
    object.insert(
        VSCODE_CLAUDE_SETTING.to_owned(),
        serde_json::Value::String(claude_wrapper.to_string_lossy().into_owned()),
    );
    object.insert(
        VSCODE_CODEX_SETTING.to_owned(),
        serde_json::Value::String(codex_wrapper.to_string_lossy().into_owned()),
    );
    let backup = backup_file(&settings)?;
    write_json_shared(&settings, &data)?;
    let restart = "Reload/restart VS Code so the extensions pick up the wrapper.";
    let message = match backup {
        Some(path) => format!(
            "Configured VS Code Claude Code + Codex extensions. {restart} (settings backup: {})",
            path.display()
        ),
        None => format!("Configured VS Code Claude Code + Codex extensions. {restart}"),
    };
    Ok(message)
}

fn uninstall_vscode_wrappers(core: &ParoleCore) -> Result<String, String> {
    // Resume any agents paused by older Prompt Parole builds, so removing coverage
    // never leaves one frozen.
    resume_vscode_agents(core);
    let dir = vscode_wrapper_dir(core);
    let settings = vscode_user_settings_path()?;
    let mut removed = 0;
    let mut manual_note = String::new();
    if settings.exists() {
        match load_vscode_settings(&settings) {
            Ok(mut data) => {
                if let Some(object) = data.as_object_mut() {
                    for key in [VSCODE_CLAUDE_SETTING, VSCODE_CODEX_SETTING] {
                        // Only remove the key if it still points at one of our wrappers.
                        let ours = object
                            .get(key)
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|value| Path::new(value).starts_with(&dir));
                        if ours {
                            object.remove(key);
                            removed += 1;
                        }
                    }
                }
                if removed > 0 {
                    let _ = backup_file(&settings)?;
                    write_json_shared(&settings, &data)?;
                }
            }
            // A JSONC settings.json (comments / trailing commas) must NOT block teardown:
            // still remove the wrapper scripts and tell the user which keys to delete.
            Err(_) => {
                manual_note = format!(
                    " Could not parse {} — remove these keys by hand: \"{VSCODE_CLAUDE_SETTING}\" and \"{VSCODE_CODEX_SETTING}\".",
                    settings.display()
                );
            }
        }
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(format!(
        "Removed VS Code coverage ({removed} setting(s)).{manual_note}"
    ))
}

/// Load VS Code settings.json, with a clearer error for the common JSONC case
/// (comments / trailing commas), which serde_json cannot parse.
fn load_vscode_settings(path: &Path) -> Result<serde_json::Value, String> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("Could not read {}: {err}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(&raw).map_err(|err| {
        format!(
            "Could not parse {} ({err}). If it contains comments or trailing commas, add these keys \
             manually instead: \"{VSCODE_CLAUDE_SETTING}\" and \"{VSCODE_CODEX_SETTING}\".",
            path.display()
        )
    })
}

fn vscode_wrapper_configured(core: &ParoleCore, key: &str) -> bool {
    let Ok(settings) = vscode_user_settings_path() else {
        return false;
    };
    let dir = vscode_wrapper_dir(core);
    load_vscode_settings(&settings)
        .ok()
        .and_then(|data| {
            data.get(key)
                .and_then(serde_json::Value::as_str)
                .map(|value| Path::new(value).starts_with(&dir))
        })
        .unwrap_or(false)
}

/// One `ps` snapshot: pid -> (ppid, comm). `comm` can contain spaces
/// (e.g. "Code Helper (Plugin)"), so everything after the two numeric columns is
/// kept as the command name.
fn ps_snapshot() -> HashMap<u32, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(output) = Command::new("ps")
        .args(["-axo", "pid=,ppid=,comm="])
        .output()
    else {
        return map;
    };
    if !output.status.success() {
        return map;
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(pid), Ok(ppid)) = (pid.parse::<u32>(), ppid.parse::<u32>()) else {
            continue;
        };
        let comm = parts.collect::<Vec<_>>().join(" ");
        map.insert(pid, (ppid, comm));
    }
    map
}

/// True if `comm` is a VS Code (or VS Code Insiders) process. Matches the app
/// bundle path and the Electron helper basename, so it works whether `ps` reports
/// a full path or a truncated basename. Cursor's "Cursor Helper" does not match.
fn comm_is_vscode(comm: &str) -> bool {
    comm.contains("Visual Studio Code") || comm.contains("Code Helper")
}

/// PIDs of claude/codex processes that descend from a VS Code process. Pure over
/// the snapshot so it is unit-testable. Terminal.app / iTerm sessions and this
/// harness do not descend from VS Code, so they are never returned — only ever
/// VS-Code-launched agents (extension chats and the integrated terminal).
fn vscode_descendant_agents(procs: &HashMap<u32, (u32, String)>) -> Vec<u32> {
    let mut out = Vec::new();
    for (&pid, (_, comm)) in procs {
        if !comm_is_agent(comm) {
            continue;
        }
        // Walk the parent chain; stop at init / a cycle (PID reuse) / depth cap.
        let mut current = procs.get(&pid).map(|(ppid, _)| *ppid);
        let mut depth = 0;
        while let Some(ancestor) = current {
            if ancestor <= 1 || depth > 24 {
                break;
            }
            let Some((grandparent, acomm)) = procs.get(&ancestor) else {
                break;
            };
            if comm_is_vscode(acomm) {
                out.push(pid);
                break;
            }
            current = Some(*grandparent);
            depth += 1;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Live PIDs of VS-Code-launched claude/codex agents.
fn vscode_agent_pids() -> Vec<u32> {
    vscode_descendant_agents(&ps_snapshot())
}

/// Resume (SIGCONT) every VS-Code-launched agent — used as a compatibility cleanup
/// for agents that older builds may have paused.
fn resume_vscode_agents(_core: &ParoleCore) {
    for pid in vscode_agent_pids() {
        let _ = Command::new("kill")
            .args(["-CONT", &pid.to_string()])
            .status();
    }
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
    write_json_shared(path, &data)?;
    Ok(backup)
}

fn uninstall_json_hook(path: &Path) -> Result<(usize, Option<PathBuf>), String> {
    let mut data = load_json_object(path)?;
    let removed = remove_prompt_parole_hooks(&mut data)?;
    if removed == 0 {
        return Ok((0, None));
    }
    let backup = backup_file(path)?;
    write_json_shared(path, &data)?;
    Ok((removed, backup))
}

fn load_json_object(path: &Path) -> Result<serde_json::Value, String> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("Could not read {}: {err}", path.display()))?;
    // An existing-but-empty/whitespace file (interrupted writer, manual clear, a tool
    // that touched the path) is a recoverable empty object, not a fatal parse error.
    if raw.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
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
    let backup = unique_path(&path.with_file_name(format!(
        "{}.bak.{stamp}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("config")
    )));
    fs::copy(path, &backup)
        .map_err(|err| format!("Could not create backup {}: {err}", backup.display()))?;
    Ok(Some(backup))
}

// ---------------------------------------------------------------------------
// App icon — minimalist padlock, Nippon palette only. Rendered procedurally so
// the window icon and the macOS .icns are always the same image.
// ---------------------------------------------------------------------------

/// Render the app icon as RGBA8 at `size`×`size`: an aomidori rounded tile with a
/// shironeri padlock. Only Nippon palette colors are used.
fn render_icon(size: u32) -> Vec<u8> {
    let s = size as f32;
    let bg = tokiwa(); // deep green tile
    let fg = shironeri(); // off-white lock

    // Rounded tile, leaving a margin so it reads as a floating macOS app icon.
    let tile_inset = s * 0.085;
    let tile_half = (s - tile_inset * 2.0) * 0.5;
    let tile_c = s * 0.5;
    let tile_radius = tile_half * 0.45;

    // Padlock body.
    let cx = s * 0.5;
    let body_cy = s * 0.60;
    let body_hx = s * 0.23;
    let body_hy = s * 0.17;
    let body_radius = s * 0.06;
    let body_top = body_cy - body_hy;

    // Shackle (inverted U above the body); legs run down into the body.
    let shackle_cy = body_top;
    let shackle_r = s * 0.135;
    let shackle_half_t = s * 0.031;
    let leg_bottom = body_cy;

    // Keyhole (circle + slot) cut back to the tile color.
    let key_cy = body_cy - s * 0.02;
    let key_r = s * 0.045;
    let slot_half_w = s * 0.015;
    let slot_bottom = key_cy + s * 0.085;

    let mut out = vec![0_u8; (size * size * 4) as usize];
    for py in 0..size {
        for px in 0..size {
            let x = px as f32 + 0.5;
            let y = py as f32 + 0.5;

            let tile_cov = coverage(sdf_round_rect(
                x,
                y,
                tile_c,
                tile_c,
                tile_half,
                tile_half,
                tile_radius,
            ));
            if tile_cov <= 0.0 {
                continue; // transparent outside the tile
            }

            let body_d = sdf_round_rect(x, y, cx, body_cy, body_hx, body_hy, body_radius);
            let shackle_d =
                sdf_shackle(x, y, cx, shackle_cy, shackle_r, leg_bottom) - shackle_half_t;
            let mut lock_cov = coverage(body_d.min(shackle_d));

            let key_d = (distance(x, y, cx, key_cy) - key_r).min(sdf_round_rect(
                x,
                y,
                cx,
                (key_cy + slot_bottom) * 0.5,
                slot_half_w,
                (slot_bottom - key_cy) * 0.5,
                slot_half_w,
            ));
            lock_cov *= 1.0 - coverage(key_d);

            let idx = ((py * size + px) * 4) as usize;
            out[idx] = mix(bg.r(), fg.r(), lock_cov);
            out[idx + 1] = mix(bg.g(), fg.g(), lock_cov);
            out[idx + 2] = mix(bg.b(), fg.b(), lock_cov);
            out[idx + 3] = (tile_cov * 255.0).round() as u8;
        }
    }
    out
}

/// Coverage in [0,1] from a signed distance (negative = inside), ~1px antialiasing.
fn coverage(distance: f32) -> f32 {
    (0.5 - distance).clamp(0.0, 1.0)
}

fn mix(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 + (b as f32 - a as f32) * t).round() as u8
}

fn distance(x: f32, y: f32, cx: f32, cy: f32) -> f32 {
    ((x - cx).powi(2) + (y - cy).powi(2)).sqrt()
}

/// Signed distance to a rounded rectangle (center, half-extents, corner radius).
fn sdf_round_rect(x: f32, y: f32, cx: f32, cy: f32, hx: f32, hy: f32, r: f32) -> f32 {
    let qx = (x - cx).abs() - hx + r;
    let qy = (y - cy).abs() - hy + r;
    let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
    let inside = qx.max(qy).min(0.0);
    outside + inside - r
}

/// Signed distance to an inverted-U centerline: a top semicircle plus two legs.
fn sdf_shackle(x: f32, y: f32, cx: f32, scy: f32, r: f32, leg_bottom: f32) -> f32 {
    let arc = if y <= scy {
        (distance(x, y, cx, scy) - r).abs()
    } else {
        distance(x, y, cx - r, scy).min(distance(x, y, cx + r, scy))
    };
    let left = dist_to_vsegment(x, y, cx - r, scy, leg_bottom);
    let right = dist_to_vsegment(x, y, cx + r, scy, leg_bottom);
    arc.min(left).min(right)
}

/// Distance from a point to a vertical segment at `vx` spanning `[y0, y1]`.
fn dist_to_vsegment(x: f32, y: f32, vx: f32, y0: f32, y1: f32) -> f32 {
    let clamped_y = y.clamp(y0.min(y1), y0.max(y1));
    distance(x, y, vx, clamped_y)
}

fn icon_data() -> egui::IconData {
    let size = 256;
    egui::IconData {
        rgba: render_icon(size),
        width: size,
        height: size,
    }
}

fn run_gui() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Prompt Parole")
            .with_inner_size([760.0, 840.0])
            .with_min_inner_size([620.0, 360.0])
            .with_icon(std::sync::Arc::new(icon_data())),
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
        // Catch a panic so a CLI command (especially the `hook`, which gates prompts)
        // fails CLOSED with exit code 2 — a panic's default abort exits non-zero in a
        // way the agent treats as "allow", silently disabling the curfew.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_cli(command, &core)));
        match result {
            Ok(Ok(code)) => std::process::exit(code),
            Ok(Err(err)) => {
                eprintln!("prompt-parole: {err}");
                std::process::exit(2);
            }
            Err(_) => {
                eprintln!("prompt-parole: internal error");
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
        let draft = WindowDraft {
            days: [true, true, false, false, false, false, false],
            ..WindowDraft::default()
        };
        assert_eq!(draft.to_cli_value().unwrap(), "19:00-05:00 mon,tue");
    }

    #[test]
    fn window_draft_rejects_no_days() {
        let draft = WindowDraft {
            days: [false; 7],
            ..WindowDraft::default()
        };
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
    fn windows_are_canonicalized_and_zero_length_rejected() {
        // Non-canonical times are canonicalized to HH:MM...
        let window = parse_window("9:00-5:30 mon").unwrap();
        assert_eq!(window.start, "09:00");
        assert_eq!(window.end, "05:30");
        // ...and a time-equal pair that differs only as a string is rejected.
        assert!(parse_window("9:00-09:00 mon").is_err());
        let config = normalize_config(Config {
            version: 1,
            timezone: "local".to_owned(),
            unlock_duration_minutes: 30,
            password_required_for: vec!["unlock".to_owned()],
            lock_windows: vec![LockWindow {
                start: "9:00".to_owned(),
                end: "09:00".to_owned(),
                days: vec!["mon".to_owned()],
            }],
            log_prompt_text: false,
        });
        assert!(config.is_err());
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
    fn schedule_resolves_lock_end_at_the_correct_dst_offset() {
        // Sat 19:00 -> Sun 05:00 across US spring-forward (2026-03-08 02:00).
        // The end is 05:00 EDT (-04:00) = 09:00 UTC, NOT 05:00 EST (-05:00).
        let config = normalize_config(Config {
            version: 1,
            timezone: "America/New_York".to_owned(),
            unlock_duration_minutes: 30,
            password_required_for: vec!["unlock".to_owned()],
            lock_windows: vec![LockWindow {
                start: "19:00".to_owned(),
                end: "05:00".to_owned(),
                days: vec!["sat".to_owned()],
            }],
            log_prompt_text: false,
        })
        .unwrap();
        let now = DateTime::parse_from_rfc3339("2026-03-07T23:00:00-05:00")
            .unwrap()
            .with_timezone(&chrono_tz::America::New_York);
        let end = scheduled_lock_until(&config, now).unwrap().unwrap();
        assert_eq!(
            end.to_utc(),
            DateTime::parse_from_rfc3339("2026-03-08T09:00:00Z")
                .unwrap()
                .to_utc()
        );
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
        // An unknown agent follows the curfew (blocks while locked) rather than
        // erroring into a permanent 24/7 block, and carries no claude-only flag.
        let unknown = core.hook_payload("bogus").unwrap().unwrap();
        assert_eq!(unknown["decision"], "block");
        assert!(unknown.get("suppressOriginalPrompt").is_none());
    }

    #[test]
    fn unlock_rejects_absurd_duration_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let core = ParoleCore {
            app_dir: dir.path().to_path_buf(),
        };
        core.setup(
            "ok",
            vec!["19:00-05:00 mon".to_owned()],
            "local".to_owned(),
            30,
            vec!["unlock".to_owned()],
        )
        .unwrap();
        assert!(core.unlock("ok", i64::MAX).is_err());
        assert!(core.unlock("ok", 0).is_err());
        assert!(core.unlock("ok", 30).is_ok());
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
    fn vscode_wrapper_gates_on_curfew_and_is_marked() {
        let script = vscode_wrapper_script(
            Path::new("/tmp/prompt-parole"),
            "exec /tmp/prompt-parole proxy --agent codex --real codex -- \"$@\"",
        );
        // Recognizable as ours, gates via `check`, then proxies outside curfew.
        assert!(script.contains("PROMPT_PAROLE_LAUNCHER=1"));
        assert!(script.contains("/tmp/prompt-parole check"));
        assert!(script.contains("exit 1"));
        assert!(script.contains("proxy --agent codex"));
    }

    #[test]
    fn proxy_blocks_new_vscode_agent_launch_when_locked() {
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

        let code = proxy_agent(&core, "codex", Path::new("/bin/cat"), &[]).unwrap();

        assert_eq!(code, 1);
    }

    #[test]
    fn vscode_descendant_matcher_targets_only_vscode_agents() {
        // Synthetic process tree:
        //   1 launchd
        //   ├─ 10 Terminal.app ─ 11 zsh ─ 12 codex      (terminal: must NOT match)
        //   ├─ 20 .../Visual Studio Code.app/.../Electron
        //   │     └─ 21 Code Helper (Plugin) ─ 22 codex (VS Code chat: MUST match)
        //   │     └─ 23 Code Helper (Plugin) ─ 24 zsh ─ 25 claude (integrated term: MUST match)
        //   └─ 30 prompt-parole ─ 31 claude              (this harness: must NOT match)
        let mut procs: HashMap<u32, (u32, String)> = HashMap::new();
        procs.insert(1, (0, "/sbin/launchd".into()));
        procs.insert(
            10,
            (1, "/System/.../Terminal.app/Contents/MacOS/Terminal".into()),
        );
        procs.insert(11, (10, "-zsh".into()));
        procs.insert(12, (11, "codex".into()));
        procs.insert(
            20,
            (
                1,
                "/Applications/Visual Studio Code.app/Contents/MacOS/Electron".into(),
            ),
        );
        procs.insert(21, (20, "Code Helper (Plugin)".into()));
        procs.insert(
            22,
            (
                21,
                "/Users/x/.vscode/extensions/openai.chatgpt-1/bin/codex".into(),
            ),
        );
        procs.insert(23, (20, "Code Helper (Plugin)".into()));
        procs.insert(24, (23, "-zsh".into()));
        procs.insert(25, (24, "claude".into()));
        procs.insert(
            30,
            (
                1,
                "/Users/x/Applications/Prompt Parole.app/Contents/MacOS/prompt-parole".into(),
            ),
        );
        procs.insert(31, (30, "claude".into()));
        assert_eq!(vscode_descendant_agents(&procs), vec![22, 25]);
    }

    #[test]
    fn vscode_descendant_matcher_survives_a_parent_cycle() {
        // PID reuse could fabricate a cycle; the depth cap must stop the walk.
        let mut procs: HashMap<u32, (u32, String)> = HashMap::new();
        procs.insert(40, (41, "codex".into()));
        procs.insert(41, (40, "-zsh".into()));
        assert!(vscode_descendant_agents(&procs).is_empty());
    }

    #[test]
    fn vscode_settings_rejects_jsonc_with_a_helpful_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // JSONC (comment) — serde_json can't parse it; we must error, not clobber.
        fs::write(&path, "{\n  // a comment\n  \"editor.fontSize\": 13\n}\n").unwrap();
        let err = load_vscode_settings(&path).unwrap_err();
        assert!(err.contains("manually"));
        // A clean object loads fine.
        fs::write(&path, "{\"editor.fontSize\": 13}\n").unwrap();
        assert_eq!(
            load_vscode_settings(&path).unwrap()["editor.fontSize"],
            serde_json::json!(13)
        );
    }

    #[test]
    fn real_agent_candidate_respects_path_order_and_skips_wrappers() {
        let dir = tempfile::tempdir().unwrap();
        let wrapper = dir.path().join("codex");
        let launcher = dir.path().join("launcher-codex");
        let real = dir.path().join("real-codex");
        let directory = dir.path().join("directory-codex");
        write_launcher_script(
            &launcher,
            Path::new("/tmp/prompt-parole"),
            "codex",
            Path::new("/opt/homebrew/bin/codex"),
        )
        .unwrap();
        fs::create_dir(&directory).unwrap();
        fs::write(&wrapper, "#!/bin/sh\n").unwrap();
        fs::write(&real, "#!/bin/sh\n").unwrap();

        let lines = [
            wrapper.to_string_lossy().to_string(),
            launcher.to_string_lossy().to_string(),
            directory.to_string_lossy().to_string(),
            real.to_string_lossy().to_string(),
        ];
        let selected = first_real_agent_candidate(lines.iter().map(String::as_str), &wrapper);

        assert_eq!(selected, Some(real));
    }

    #[test]
    fn usable_agent_candidate_rejects_wrappers_and_non_files() {
        let dir = tempfile::tempdir().unwrap();
        let wrapper = dir.path().join("codex");
        let launcher = dir.path().join("launcher-codex");
        let directory = dir.path().join("codex-dir");
        let real = dir.path().join("real-codex");

        write_launcher_script(
            &launcher,
            Path::new("/tmp/prompt-parole"),
            "codex",
            Path::new("/opt/homebrew/bin/codex"),
        )
        .unwrap();
        fs::create_dir(&directory).unwrap();
        fs::write(&wrapper, "#!/bin/sh\n").unwrap();
        fs::write(&real, "#!/bin/sh\n").unwrap();

        assert!(!usable_agent_candidate(&wrapper, Some(&wrapper)));
        assert!(!usable_agent_candidate(&launcher, Some(&wrapper)));
        assert!(!usable_agent_candidate(&directory, Some(&wrapper)));
        assert!(usable_agent_candidate(&real, Some(&wrapper)));
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
    fn locked_enforcement_does_not_stop_running_agents() {
        let source = include_str!("main.rs");
        for forbidden in [
            ["-", "STOP"].concat(),
            ["SIG", "STOP"].concat(),
            ["manage", "_terminal", "_codex", "_pause"].concat(),
            ["manage", "_vscode", "_suspension"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "locked enforcement must not stop running agents: found {forbidden}"
            );
        }
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
    fn watchdog_backoff_sleep_is_bounded() {
        let now = Instant::now();

        assert_eq!(
            watchdog_backoff_sleep(now, now + StdDuration::from_secs(300)),
            StdDuration::from_secs(60)
        );
        assert_eq!(
            watchdog_backoff_sleep(now, now + StdDuration::from_secs(12)),
            StdDuration::from_secs(12)
        );
        assert_eq!(watchdog_backoff_sleep(now, now), StdDuration::from_secs(0));
    }

    #[test]
    fn watchdog_retries_once_after_permission_backoff() {
        assert_eq!(watchdog_attempt_limit(false), 3);
        assert_eq!(watchdog_attempt_limit(true), 1);
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
        assert!(plist.contains("<key>CFBundleIconFile</key>"));
        assert!(plist.contains("<string>AppIcon</string>"));
    }

    #[test]
    fn icon_is_rgba_with_transparent_corners_and_opaque_center() {
        let size = 64;
        let rgba = render_icon(size);
        assert_eq!(rgba.len(), (size * size * 4) as usize);
        let alpha = |x: u32, y: u32| rgba[((y * size + x) * 4 + 3) as usize];
        // Corners sit outside the rounded tile -> transparent.
        assert_eq!(alpha(0, 0), 0);
        assert_eq!(alpha(size - 1, size - 1), 0);
        // Center sits inside the tile -> opaque.
        assert_eq!(alpha(size / 2, size / 2), 255);
        // The lock (shironeri) is brighter than the tile (aomidori): some pixel is light.
        let lightest = (0..size * size)
            .map(|i| rgba[(i * 4) as usize] as u32)
            .max()
            .unwrap();
        assert!(
            lightest > 200,
            "expected a light lock pixel, got {lightest}"
        );
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
        // Third-party terminal emulators that title with the running command.
        assert!(window_is_agent_target("iTerm2", "claude"));
        assert!(window_is_agent_target("Ghostty", "~ — codex"));
        assert!(window_is_agent_target("WezTerm", "codex session"));
        assert!(!window_is_agent_target("Terminal", "plain zsh"));
        assert!(!window_is_agent_target("Google Chrome", "codex docs"));
        // A terminal not running an agent (title does not mention it) must not match.
        assert!(!window_is_agent_target("iTerm2", "vim notes.txt"));
    }

    #[test]
    fn process_tree_detects_agent_descendant() {
        // 100 (iTerm2) -> 200 (zsh) -> 300 (claude)
        let rows = vec![
            (
                100,
                1,
                "/Applications/iTerm.app/Contents/MacOS/iTerm2".to_owned(),
            ),
            (200, 100, "/bin/zsh".to_owned()),
            (300, 200, "/opt/homebrew/bin/claude".to_owned()),
            (400, 1, "/usr/bin/vim".to_owned()),
        ];
        assert!(tree_has_agent(&rows, 100));
        assert!(tree_has_agent(&rows, 200));
        assert!(tree_has_agent(&rows, 300));
        assert!(!tree_has_agent(&rows, 400));
        assert!(!tree_has_agent(&rows, 999));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_proc_row_handles_real_padded_ps_output() {
        // Real `ps -o pid=,ppid=,comm=` pads columns with runs of spaces.
        assert_eq!(
            parse_proc_row("           332                       1       /usr/libexec/logd"),
            Some((332, 1, "/usr/libexec/logd".to_owned()))
        );
        // A comm path containing spaces must be preserved intact.
        assert_eq!(
            parse_proc_row(
                "  500   1   /Applications/Visual Studio Code.app/Contents/MacOS/Electron"
            ),
            Some((
                500,
                1,
                "/Applications/Visual Studio Code.app/Contents/MacOS/Electron".to_owned()
            ))
        );
        // Single-space rows still work; junk/header rows are rejected.
        assert_eq!(
            parse_proc_row("42 7 /bin/zsh"),
            Some((42, 7, "/bin/zsh".to_owned()))
        );
        assert_eq!(parse_proc_row(""), None);
        assert_eq!(parse_proc_row("PID PPID COMM"), None);
    }

    #[test]
    fn process_tree_does_not_loop_on_cycles() {
        // Defensive: a malformed parent cycle must terminate.
        let rows = vec![(1, 2, "/bin/a".to_owned()), (2, 1, "/bin/b".to_owned())];
        assert!(!tree_has_agent(&rows, 1));
    }

    #[test]
    fn guard_process_matcher_matches_only_real_guard_command() {
        let local = "/Users/jake/.local/bin/prompt-parole";
        assert!(process_matches(local, &format!("{local} guard"), "guard"));
        assert!(!process_matches(
            local,
            &format!("{local} guard-agent --action stop"),
            "guard"
        ));
        // prompt-parole as an argument to another program (its comm is the shell) must not match.
        assert!(!process_matches(
            "/bin/zsh",
            &format!("/bin/zsh -c {local} guard"),
            "guard"
        ));
        assert!(!process_matches(
            local,
            &format!("{local} guard-watchdog"),
            "guard"
        ));
        assert!(process_matches(
            local,
            &format!("{local} guard-watchdog"),
            "guard-watchdog"
        ));
        // App-bundle install: executable path contains a space; must still match (regression).
        let bundle = "/Users/jake/Applications/Prompt Parole.app/Contents/MacOS/prompt-parole";
        assert!(process_matches(bundle, &format!("{bundle} guard"), "guard"));
        assert!(process_matches(
            bundle,
            &format!("{bundle} guard-watchdog --interval-seconds 2"),
            "guard-watchdog"
        ));
        assert!(!process_matches(
            bundle,
            &format!("{bundle} guard"),
            "guard-watchdog"
        ));
    }

    #[test]
    fn split_pid_line_separates_pid_from_rest() {
        assert_eq!(
            split_pid_line("  123 /usr/bin/thing arg"),
            Some((123, "/usr/bin/thing arg"))
        );
        assert_eq!(split_pid_line("notpid x"), None);
    }

    #[test]
    fn nippon_palette_values_are_exact_nipponcolors() {
        // Exact hex from nipponcolors.com.
        assert_eq!(shironeri(), egui::Color32::from_rgb(252, 250, 242)); // #FCFAF2
        assert_eq!(gofun(), egui::Color32::from_rgb(255, 255, 251)); // #FFFFFB
        assert_eq!(torinoko(), egui::Color32::from_rgb(218, 201, 166)); // #DAC9A6
        assert_eq!(seiji(), egui::Color32::from_rgb(105, 176, 172)); // #69B0AC
        assert_eq!(tokiwa(), egui::Color32::from_rgb(0, 123, 67)); // #007B43
        assert_eq!(asagi(), egui::Color32::from_rgb(51, 166, 184)); // #33A6B8
        assert_eq!(yamabuki(), egui::Color32::from_rgb(255, 177, 27)); // #FFB11B
        assert_eq!(enji(), egui::Color32::from_rgb(159, 53, 58)); // #9F353A
        assert_eq!(sumi(), egui::Color32::from_rgb(28, 28, 28)); // #1C1C1C
        assert_eq!(nibi(), egui::Color32::from_rgb(101, 103, 101)); // #656765
    }

    #[test]
    fn load_json_object_treats_empty_file_as_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Existing-but-empty and whitespace-only files must not abort install/uninstall.
        std::fs::write(&path, "").unwrap();
        assert_eq!(load_json_object(&path).unwrap(), serde_json::json!({}));
        std::fs::write(&path, "  \n\t ").unwrap();
        assert_eq!(load_json_object(&path).unwrap(), serde_json::json!({}));
        // A non-existent file is still the empty object.
        assert_eq!(
            load_json_object(&dir.path().join("nope.json")).unwrap(),
            serde_json::json!({})
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_json_shared_writes_through_a_symlinked_config() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-settings.json");
        std::fs::write(&target, "{}").unwrap();
        let link = dir.path().join("settings.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // resolve_symlink_target follows the link to the real file; a regular file -> None.
        assert_eq!(
            resolve_symlink_target(&link).as_deref(),
            Some(target.as_path())
        );
        assert_eq!(resolve_symlink_target(&target), None);

        // Writing through the link updates the TARGET and keeps the symlink intact, so a
        // dotfiles-managed config keeps receiving changes instead of being detached.
        write_json_shared(&link, &serde_json::json!({"k": 1})).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        assert_eq!(written, serde_json::json!({"k": 1}));
    }

    #[test]
    fn vscode_wrapper_fails_closed_on_check_error() {
        let script = vscode_wrapper_script(
            Path::new("/tmp/prompt-parole"),
            "exec /tmp/prompt-parole proxy --agent codex --real codex -- \"$@\"",
        );
        // Any non-zero `check` exit (1 = curfew, 2 = status/config error) blocks, so a
        // corrupt config cannot silently allow a new VS Code agent session.
        assert!(script.contains("check >/dev/null 2>&1"));
        assert!(script.contains("-ne 0"));
        assert!(!script.contains("-eq 1"));
    }
}
