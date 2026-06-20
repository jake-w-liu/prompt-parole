# Prompt Parole

Your AI coding assistant is not the problem. The tenth "one tiny follow-up
prompt" after dinner might be.

Prompt Parole is a local curfew gate for Claude Code and Codex. During your
lock window, new prompts are blocked unless the password is entered through the
separate `prompt-parole unlock` command or the local GUI. You can still inspect
files, watch progress, read diffs, and generally look responsible. You just
cannot keep feeding the prompt machine after curfew without parole.

Repository: <https://github.com/jake-w-liu/prompt-parole>

## What It Does

- Blocks Claude Code and Codex prompts during configured hours.
- Uses `UserPromptSubmit` hooks, so the prompt is stopped before the agent sees
  it.
- Sets the password once with double entry.
- Changes the password only after the current password is entered.
- Saves only a slow password hash, never the password.
- Logs block/unlock events, but does not log prompt text by default.
- Provides a native Rust desktop GUI because editing JSON by hand is how "just
  one more minute" becomes 2:13 AM.

## Install

From a checkout:

```sh
python3 -m pip install -e .
prompt-parole setup
prompt-parole install
```

After installing hooks, start a new Claude Code or Codex session.

Once the repo is public, this should work too:

```sh
python3 -m pip install git+https://github.com/jake-w-liu/prompt-parole.git
```

## Desktop GUI

Prompt Parole includes a native Rust desktop app. It is not a browser page, so
Google Password Manager and browser-generated-password prompts are not involved.
The desktop app calls the installed `prompt-parole` CLI, which keeps the hook
logic and password hashing in one place.

Build and run it from the checkout:

```sh
cargo run --manifest-path desktop/Cargo.toml
```

For a release binary:

```sh
cargo build --release --manifest-path desktop/Cargo.toml
desktop/target/release/prompt-parole-desktop
```

If the app cannot find the CLI, set `PROMPT_PAROLE_CLI`:

```sh
PROMPT_PAROLE_CLI="$HOME/.local/bin/prompt-parole" desktop/target/release/prompt-parole-desktop
```

The first screen sets the password, default unlock duration, timezone, and lock
windows. Lock windows are selected with start/end dropdowns and day checkboxes;
no raw JSON editing is required. After setup, the same app can save settings,
temporarily unlock prompts, clear a temporary unlock, and change the password.

The "Suggest Local Password" button generates a local password and fills both
new-password boxes. It does not save it anywhere. If the password is forgotten,
Prompt Parole has no recovery command; retrieve it from wherever you stored it,
or the gate will need to be removed outside the app.

## Daily Use

```sh
prompt-parole status
prompt-parole unlock
prompt-parole lock
prompt-parole passwd
prompt-parole configure --lock-window "19:00-05:00 mon,tue,wed,thu,fri,sat,sun"
prompt-parole gui
```

The default lock window is every day from `19:00` to `05:00` in your local time
zone.

`prompt-parole gui` still starts the older local-only browser settings page on
`127.0.0.1`, but the Rust desktop app is the recommended GUI. Saving settings,
changing the password, and temporary unlocks all require the current password.
The GUIs use a restrained traditional Japanese palette inspired by Nippon Colors
and Sanzo Wada-style color-combination references, because a relationship-saving
tool should not look like a router admin page.

## Config

The generated config looks like this:

```json
{
  "lock_windows": [
    {
      "start": "19:00",
      "end": "05:00",
      "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    }
  ],
  "timezone": "local",
  "unlock_duration_minutes": 30,
  "password_required_for": ["configure", "disable", "install", "passwd", "uninstall", "unlock"],
  "log_prompt_text": false
}
```

`unlock`, `passwd`, `configure`, `install`, and `uninstall` are always
password-gated after setup even if a config edit tries to remove them. The app
is polite, not gullible.

Lock windows can be written as either:

```text
19:00-05:00
19:00-05:00 mon,tue,wed,thu,fri
```

## Hook Behavior

The installed hook commands are:

```sh
prompt-parole hook --agent claude-code
prompt-parole hook --agent codex
```

When locked, the hook emits:

```json
{"decision":"block","reason":"Prompt Parole: curfew is active until ..."}
```

When allowed, it emits nothing and exits successfully.

## Security Model

Prompt Parole has no recovery command. If the password is lost, the app will not
unlock itself.

That does not make a local machine into a bank vault. If your operating-system
account can edit your Claude/Codex configs, delete `~/.prompt-parole`, or run
the tools with hook-bypass flags, you can remove the gate. For a stronger
setup, install and protect the hook files from an admin account you do not use
day to day.

In plain language: Prompt Parole can stop a habit. It cannot defeat the person
who owns the laptop and is currently arguing with a shell prompt.

## Verification

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m compileall -q src tests
PYTHONPATH=src python3 -m prompt_parole --help
```

## Name

Why "Prompt Parole"? Because the prompts are not banned forever. They are just
required to check in with a responsible adult after hours.
