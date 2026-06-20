from __future__ import annotations

import html
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from .app import PromptParole
from .errors import PromptParoleError
from .policy import DAY_NAMES, PASSWORD_ACTIONS


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _window_lines(config: dict[str, Any]) -> str:
    lines = []
    for window in config["lock_windows"]:
        days = ",".join(window["days"])
        lines.append(f"{window['start']}-{window['end']} {days}")
    return "\n".join(lines)


def _parse_window_lines(raw: str) -> list[str]:
    windows = []
    for line in raw.splitlines():
        clean = line.strip()
        if clean:
            windows.append(clean)
    return windows


def _checked(name: str, values: list[str]) -> str:
    return " checked" if name in values else ""


def render_page(app: PromptParole, message: str = "", error: str = "") -> str:
    configured = app.is_configured()
    config = app.load_config()
    decision = app.decision() if configured else None
    action_values = config["password_required_for"]
    status = "not configured"
    if decision:
        status = "allowed" if decision.allowed else "blocked"
    windows = _esc(_window_lines(config))
    message_html = f'<div class="notice">{_esc(message)}</div>' if message else ""
    error_html = f'<div class="error">{_esc(error)}</div>' if error else ""
    day_hint = ", ".join(DAY_NAMES)
    action_boxes = "\n".join(
        f'<label><input type="checkbox" name="password_required_for" value="{_esc(action)}"{_checked(action, action_values)}> {_esc(action)}</label>'
        for action in sorted(PASSWORD_ACTIONS)
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Prompt Parole</title>
  <style>
    :root {{
      color-scheme: light dark;
      --shironeri: #ffddca;
      --sumi: #27221f;
      --aisumicha: #393432;
      --aomidori: #3a6960;
      --asagi: #48929b;
      --seiji: #819c8b;
      --yamabuki: #ffa400;
      --enji: #9d2933;
      --torinoko: #e2be9f;
      --kamenozoki: #c6c2b6;
      --rikyunezumi: #656255;
      --bg: var(--shironeri);
      --fg: var(--sumi);
      --muted: var(--rikyunezumi);
      --line: rgba(57, 52, 50, 0.22);
      --accent: var(--aomidori);
      --accent-2: var(--asagi);
      --danger: var(--enji);
      --panel: rgba(255, 221, 202, 0.72);
      --field: rgba(255, 255, 255, 0.42);
      --button-fg: #fffffb;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #23191e;
        --fg: var(--shironeri);
        --muted: var(--kamenozoki);
        --line: rgba(198, 194, 182, 0.24);
        --accent: var(--seiji);
        --accent-2: var(--asagi);
        --danger: #f58f84;
        --panel: rgba(57, 52, 50, 0.74);
        --field: rgba(39, 34, 31, 0.72);
        --button-fg: #171412;
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--fg);
      font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width: min(980px, calc(100vw - 32px));
      margin: 24px auto 48px;
    }}
    header {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 16px;
      align-items: end;
      border-bottom: 2px solid var(--aisumicha);
      padding: 18px 0 15px;
    }}
    h1 {{ font-size: 30px; margin: 0; letter-spacing: 0; }}
    h2 {{ font-size: 18px; margin: 26px 0 12px; letter-spacing: 0; }}
    .status {{
      color: var(--button-fg);
      background: var(--aisumicha);
      border: 1px solid var(--aisumicha);
      border-radius: 999px;
      padding: 6px 12px;
      font-weight: 700;
      white-space: nowrap;
    }}
    .palette {{
      display: grid;
      grid-template-columns: repeat(8, minmax(0, 1fr));
      height: 8px;
      border-bottom: 1px solid var(--line);
    }}
    .palette span {{ display: block; }}
    .notice, .error {{
      margin-top: 16px;
      padding: 10px 12px;
      background: var(--panel);
      border-left: 4px solid var(--accent);
    }}
    .error {{ border-left-color: var(--danger); }}
    form {{
      display: grid;
      gap: 14px;
      padding: 18px 0 16px;
      border-bottom: 1px solid var(--line);
    }}
    label {{ display: grid; gap: 6px; color: var(--muted); }}
    input, textarea {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      color: var(--fg);
      background: var(--field);
      font: inherit;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.16);
    }}
    input:focus, textarea:focus {{
      outline: 3px solid color-mix(in srgb, var(--accent-2) 34%, transparent);
      border-color: var(--accent-2);
    }}
    textarea {{
      min-height: 96px;
      resize: vertical;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    .row {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
    .checks {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px 14px; }}
    .checks label {{ display: flex; align-items: center; gap: 8px; color: var(--fg); }}
    .checks input {{ width: auto; }}
    .hint {{ color: var(--muted); font-size: 13px; }}
    button {{
      width: fit-content;
      border: 1px solid var(--accent);
      border-radius: 6px;
      padding: 9px 14px;
      color: var(--button-fg);
      background: var(--accent);
      font: inherit;
      font-weight: 650;
      cursor: pointer;
    }}
    button:hover {{ background: var(--accent-2); border-color: var(--accent-2); }}
    .secondary {{ background: transparent; color: var(--accent); }}
    @media (max-width: 640px) {{
      header, .row {{ grid-template-columns: 1fr; display: grid; }}
      .status {{ width: fit-content; }}
      button {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Prompt Parole</h1>
      <div class="status">Prompts: {_esc(status)}</div>
    </header>
    <div class="palette" aria-label="Traditional Japanese color palette">
      <span style="background:#ffddca" title="shironeri"></span>
      <span style="background:#e2be9f" title="torinoko"></span>
      <span style="background:#819c8b" title="seiji"></span>
      <span style="background:#3a6960" title="aomidori"></span>
      <span style="background:#48929b" title="asagi"></span>
      <span style="background:#ffa400" title="yamabuki"></span>
      <span style="background:#9d2933" title="enji"></span>
      <span style="background:#27221f" title="sumi"></span>
    </div>
    {message_html}
    {error_html}

    <h2>Settings</h2>
    <form method="post" action="/configure">
      <label>Current password
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <label>Lock windows
        <textarea name="lock_windows" spellcheck="false">{windows}</textarea>
        <span class="hint">One per line: HH:MM-HH:MM or HH:MM-HH:MM mon,tue. Days: {_esc(day_hint)}.</span>
      </label>
      <div class="row">
        <label>Timezone
          <input name="timezone" value="{_esc(config['timezone'])}">
        </label>
        <label>Unlock duration, minutes
          <input name="unlock_duration_minutes" type="number" min="1" value="{_esc(config['unlock_duration_minutes'])}">
        </label>
      </div>
      <label>Password required for</label>
      <div class="checks">{action_boxes}</div>
      <button type="submit">Save Settings</button>
    </form>

    <h2>Unlock</h2>
    <form method="post" action="/unlock">
      <div class="row">
        <label>Password
          <input type="password" name="password" autocomplete="current-password" required>
        </label>
        <label>Duration, minutes
          <input name="duration_minutes" type="number" min="1" placeholder="{_esc(config['unlock_duration_minutes'])}">
        </label>
      </div>
      <button type="submit">Unlock</button>
    </form>

    <h2>Password</h2>
    <form method="post" action="/passwd">
      <label>Current password
        <input type="password" name="current_password" autocomplete="current-password" required>
      </label>
      <div class="row">
        <label>New password
          <input type="password" name="new_password" autocomplete="new-password" required>
        </label>
        <label>New password again
          <input type="password" name="new_password_again" autocomplete="new-password" required>
        </label>
      </div>
      <button type="submit">Change Password</button>
    </form>

    <h2>Manual Lock</h2>
    <form method="post" action="/lock">
      <button class="secondary" type="submit">Clear Temporary Unlock</button>
    </form>
  </main>
</body>
</html>
"""


class PromptParoleHandler(BaseHTTPRequestHandler):
    app = PromptParole()

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _send_html(self, body: str, status: int = 200) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _form(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        return parse_qs(raw, keep_blank_values=True)

    def _value(self, form: dict[str, list[str]], name: str, default: str = "") -> str:
        values = form.get(name)
        return values[0] if values else default

    def do_GET(self) -> None:
        if self.path != "/":
            self.send_error(404)
            return
        self._send_html(render_page(self.app))

    def do_POST(self) -> None:
        try:
            form = self._form()
            if self.path == "/configure":
                windows = _parse_window_lines(self._value(form, "lock_windows"))
                duration = int(self._value(form, "unlock_duration_minutes"))
                actions = [str(value).lower() for value in form.get("password_required_for", [])]
                self.app.configure(
                    self._value(form, "password"),
                    lock_windows=windows,
                    timezone_name=self._value(form, "timezone", "local"),
                    unlock_duration_minutes=duration,
                    password_required_for=actions,
                )
                self._send_html(render_page(self.app, message="Settings saved."))
                return
            if self.path == "/unlock":
                raw_duration = self._value(form, "duration_minutes").strip()
                duration = int(raw_duration) if raw_duration else None
                expires = self.app.unlock(self._value(form, "password"), duration_minutes=duration)
                display = expires.strftime("%Y-%m-%d %H:%M %Z").strip()
                self._send_html(render_page(self.app, message=f"Unlocked until {display}."))
                return
            if self.path == "/passwd":
                new_password = self._value(form, "new_password")
                if new_password != self._value(form, "new_password_again"):
                    raise PromptParoleError("Passwords do not match.")
                self.app.change_password(self._value(form, "current_password"), new_password)
                self._send_html(render_page(self.app, message="Password changed."))
                return
            if self.path == "/lock":
                self.app.lock()
                self._send_html(render_page(self.app, message="Temporary unlock cleared."))
                return
            self.send_error(404)
        except (PromptParoleError, ValueError) as exc:
            self._send_html(render_page(self.app, error=str(exc)), status=400)


def run_gui(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    open_browser: bool = True,
    app: PromptParole | None = None,
) -> None:
    handler = type("BoundPromptParoleHandler", (PromptParoleHandler,), {"app": app or PromptParole()})
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_port}/"
    if open_browser:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    print(f"Prompt Parole GUI running at {url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPrompt Parole GUI stopped.")
    finally:
        server.server_close()
