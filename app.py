import os
import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, flash, abort
)

app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not SECRET_KEY:
    raise RuntimeError("Missing SECRET_KEY environment variable")
if not ADMIN_PASSWORD:
    raise RuntimeError("Missing ADMIN_PASSWORD environment variable")
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "1") == "1",
    MAX_CONTENT_LENGTH=250_000,
)

# On Render, set DB_PATH to a file under your mounted persistent disk,
# for example /var/data/dashboard.db. Without a disk, local SQLite data is ephemeral.
DB_PATH = os.getenv("DB_PATH", str(Path(__file__).with_name("dashboard.db")))
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

DEFAULTS = {
    "auto_reply_enabled": "0",
    "auto_reply_text": "Thanks for your message! I'll get back to you soon.",
    "group_name_target": "",
    "nickname_target_id": "",
    "nickname_value": "",
    "theme": "dark",
}
DEFAULT_RULES = [
    {"keyword": "hello", "reply": "Hello! How can I help?", "enabled": True},
]

def db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        con.execute("""CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS reply_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL, reply TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
        )""")
        for key, value in DEFAULTS.items():
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (key, value))
        count = con.execute("SELECT COUNT(*) AS n FROM reply_rules").fetchone()["n"]
        if count == 0:
            for rule in DEFAULT_RULES:
                con.execute(
                    "INSERT INTO reply_rules(keyword,reply,enabled) VALUES(?,?,?)",
                    (rule["keyword"], rule["reply"], int(rule["enabled"]))
                )

def log_event(level, message):
    # Never pass secrets, cookie values, or raw request bodies here.
    with db() as con:
        con.execute(
            "INSERT INTO logs(created_at,level,message) VALUES(?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), level, str(message)[:500]),
        )

def get_settings():
    with db() as con:
        rows = con.execute("SELECT key,value FROM settings").fetchall()
    values = DEFAULTS.copy()
    values.update({r["key"]: r["value"] for r in rows})
    return values

def save_settings(values):
    with db() as con:
        for key, value in values.items():
            if key in DEFAULTS:
                con.execute("""INSERT INTO settings(key,value) VALUES(?,?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (key, str(value)))

def get_rules():
    with db() as con:
        return con.execute("SELECT * FROM reply_rules ORDER BY id DESC").fetchall()

def recent_logs(limit=100):
    with db() as con:
        return con.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()

def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token

def csrf_protect():
    sent = request.form.get("_csrf", "")
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, "Invalid or expired form token. Reload the page and try again.")

@app.context_processor
def inject_globals():
    return {"csrf": csrf_token()}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

BASE = r"""
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Messenger Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0c1018;--panel:#151c29;--line:#2a3548;--text:#edf2ff;--muted:#9ba9c0;--accent:#8ea3ff}
body.light{color-scheme:light;--bg:#f3f5fa;--panel:#fff;--line:#d8deea;--text:#182033;--muted:#58647a;--accent:#667cf0}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,Arial}
.wrap{max-width:1100px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:26px;margin:0}h2{font-size:18px;margin:0 0 14px}.muted,small{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-top:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin-top:16px}
label{display:block;color:var(--muted);margin:12px 0 6px}input,textarea,select{width:100%;padding:12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--text)}
textarea{min-height:85px;resize:vertical}button,.btn{display:inline-block;padding:11px 14px;border:0;border-radius:9px;background:var(--accent);color:#10172b;font-weight:700;cursor:pointer;text-decoration:none;margin-top:12px}
.btn.secondary,button.secondary{background:var(--line);color:var(--text)}.status{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:5px 9px;color:var(--muted);font-size:12px}
.notice{padding:12px 14px;background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-top:16px}
.log{padding:10px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.log:last-child{border:0}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted)}
.inline{display:inline}.inline button{margin:0}.smallbtn{padding:7px 9px;margin:0}
@media(max-width:520px){.wrap{padding:16px}.card{padding:16px}h1{font-size:22px}}
</style></head>
<body class="{{ 'light' if settings and settings.theme == 'light' else 'dark' }}">
<div class="wrap">
<header class="top"><div><h1>Messenger Dashboard</h1><div class="muted">Configuration and activity</div></div>
{% if logged %}<div><a class="btn secondary" href="{{ url_for('index') }}">Dashboard</a> <a class="btn secondary" href="{{ url_for('logs') }}">Logs</a> <a class="btn secondary" href="{{ url_for('logout') }}">Log out</a></div>{% endif %}</header>
{% with messages = get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}
{{ body|safe }}
</div></body></html>
"""

LOGIN = r"""
<div class="card" style="max-width:460px;margin:28px auto">
<h2>Sign in</h2><p class="muted">Use the dashboard password configured in your hosting environment.</p>
<form method="post">
<input type="hidden" name="_csrf" value="{{ csrf }}">
<label>Dashboard password</label><input type="password" name="password" required autocomplete="current-password">
<button type="submit">Sign in</button></form></div>
"""

DASH = r"""
<div class="notice"><strong>Integration status: configuration-only.</strong> The official Messenger Platform is Page-focused; it does not provide general-purpose access to arbitrary personal Messenger group chats, group names, or member nicknames. Controls here save configuration or log a request; they do not claim to have changed a live chat.</div>
<div class="grid">
<section class="card"><h2>Auto-reply settings</h2>
<form method="post" action="{{ url_for('save_settings_route') }}">
<input type="hidden" name="_csrf" value="{{ csrf }}">
<label><input style="width:auto" type="checkbox" name="auto_reply_enabled" value="1" {% if s.auto_reply_enabled == '1' %}checked{% endif %}> Enable auto-reply configuration</label>
<label>Fallback reply text</label><textarea name="auto_reply_text" maxlength="2000" required>{{ s.auto_reply_text }}</textarea>
<button type="submit">Save settings</button></form>
<p class="muted"><small>Saved configuration only; no Messenger messages are sent.</small></p></section>
<section class="card"><h2>Group-name request</h2><form method="post" action="{{ url_for('request_action') }}">
<input type="hidden" name="_csrf" value="{{ csrf }}"><input type="hidden" name="action" value="group_name">
<label>Target group/thread reference</label><input name="target" maxlength="200" placeholder="Optional reference">
<label>Desired group name</label><input name="value" maxlength="100" value="{{ s.group_name_target }}" required>
<button type="submit">Log rename request</button></form><p class="muted"><small>Records a request only; no live rename is performed.</small></p></section>
<section class="card"><h2>Nickname request</h2><form method="post" action="{{ url_for('request_action') }}">
<input type="hidden" name="_csrf" value="{{ csrf }}"><input type="hidden" name="action" value="nickname">
<label>Target participant reference</label><input name="target" maxlength="200" value="{{ s.nickname_target_id }}" placeholder="Optional reference">
<label>Desired nickname</label><input name="value" maxlength="100" value="{{ s.nickname_value }}" required>
<button type="submit">Log nickname request</button></form><p class="muted"><small>Records a request only; no live nickname change is performed.</small></p></section>
<section class="card"><h2>Appearance</h2><form method="post" action="{{ url_for('save_theme') }}"><input type="hidden" name="_csrf" value="{{ csrf }}">
<label>Dashboard theme</label><select name="theme"><option value="dark" {% if s.theme != 'light' %}selected{% endif %}>Dark</option><option value="light" {% if s.theme == 'light' %}selected{% endif %}>Light</option></select>
<button type="submit">Save theme</button></form><p class="muted"><small>Theme preference is saved in SQLite.</small></p></section>
<section class="card"><h2>Connection</h2><p><span class="status">Not connected to Messenger</span></p>
<p class="muted">For eligible Page conversations, see Meta's official documentation. A Page token does not grant access to arbitrary personal group chats.</p>
<a class="btn secondary" href="https://developers.facebook.com/docs/messenger-platform/" target="_blank" rel="noreferrer">Official API docs</a></section>
</div>
<section class="card"><h2>Auto-reply rules</h2><p class="muted">Rules are stored for configuration/testing; they are not connected to live Messenger messages.</p>
<form method="post" action="{{ url_for('add_rule') }}"><input type="hidden" name="_csrf" value="{{ csrf }}">
<label>Keyword or phrase</label><input name="keyword" maxlength="100" required placeholder="e.g. hours">
<label>Reply</label><textarea name="reply" maxlength="2000" required placeholder="Reply text for this rule"></textarea><button type="submit">Add rule</button></form>
{% if rules %}<table><thead><tr><th>Keyword</th><th>Reply</th><th>Enabled</th><th>Action</th></tr></thead><tbody>
{% for rule in rules %}<tr><td>{{ rule.keyword }}</td><td>{{ rule.reply }}</td><td>{{ 'Yes' if rule.enabled else 'No' }}</td><td>
<form class="inline" method="post" action="{{ url_for('toggle_rule', rule_id=rule.id) }}"><input type="hidden" name="_csrf" value="{{ csrf }}"><button class="secondary smallbtn" type="submit">{{ 'Disable' if rule.enabled else 'Enable' }}</button></form>
<form class="inline" method="post" action="{{ url_for('delete_rule', rule_id=rule.id) }}" onsubmit="return confirm('Delete this rule?')"><input type="hidden" name="_csrf" value="{{ csrf }}"><button class="secondary smallbtn" type="submit">Delete</button></form>
</td></tr>{% endfor %}</tbody></table>{% else %}<p class="muted">No rules configured yet.</p>{% endif %}</section>
<section class="card"><h2>Command panel</h2><p class="muted">Commands update configuration or create log entries only.</p>
<form method="post" action="{{ url_for('command') }}"><input type="hidden" name="_csrf" value="{{ csrf }}">
<label>Command</label><select name="cmd"><option value="status">status — show integration status</option><option value="logs">logs — record a log entry</option><option value="reply_on">reply on — enable reply configuration</option><option value="reply_off">reply off — disable reply configuration</option></select><button type="submit">Run command</button></form>
{% for item in logs[:6] %}<div class="log"><small>{{ item.created_at }} · {{ item.level }}</small><div>{{ item.message }}</div></div>{% endfor %}</section>
<section class="card"><h2>Cookie JSON structure validator</h2><form method="post" action="{{ url_for('validate_cookie_json') }}"><input type="hidden" name="_csrf" value="{{ csrf }}">
<label>Optional JSON syntax check</label><textarea name="cookie_json" maxlength="200000" placeholder='[{"name":"example","value":"REDACTED","domain":".facebook.com"}]' required></textarea>
<button type="submit">Validate JSON structure</button></form><p class="muted"><small>Do not paste real session cookies. This checks JSON syntax/shape only; submitted values are not saved, logged, echoed, or used to sign in.</small></p></section>
"""

LOGS = r"""
<section class="card"><h2>Activity logs</h2><p class="muted">Latest 500 configuration events. Secret values and raw cookie contents are not recorded.</p>
{% for item in logs %}<div class="log"><small>{{ item.created_at }} · {{ item.level }}</small><div>{{ item.message }}</div></div>{% else %}<p class="muted">No logs yet.</p>{% endfor %}</section>
"""

@app.before_request
def csrf_guard():
    if request.method == "POST" and request.endpoint != "login":
        csrf_protect()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        csrf_protect()
        supplied = request.form.get("password", "")
        if hmac.compare_digest(supplied, ADMIN_PASSWORD):
            session.clear()
            session["logged_in"] = True
            session["_csrf"] = secrets.token_urlsafe(32)
            log_event("INFO", "Dashboard login successful.")
            return redirect(url_for("index"))
        log_event("WARN", "Failed dashboard login attempt.")
        flash("Invalid password.")
    return render_template_string(BASE, body=render_template_string(LOGIN), logged=False, settings=None)

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    s = get_settings()
    body = render_template_string(DASH, s=s, rules=get_rules(), logs=recent_logs(100))
    return render_template_string(BASE, body=body, logged=True, settings=s)

@app.route("/logs")
@login_required
def logs():
    return render_template_string(BASE, body=render_template_string(LOGS, logs=recent_logs(500)),
                                  logged=True, settings=get_settings())

@app.route("/settings", methods=["POST"])
@login_required
def save_settings_route():
    values = {
        "auto_reply_enabled": "1" if request.form.get("auto_reply_enabled") == "1" else "0",
        "auto_reply_text": request.form.get("auto_reply_text", DEFAULTS["auto_reply_text"]).strip()[:2000],
    }
    save_settings(values)
    log_event("INFO", "Auto-reply configuration saved.")
    flash("Settings saved. No Messenger message was sent.")
    return redirect(url_for("index"))

@app.route("/theme", methods=["POST"])
@login_required
def save_theme():
    theme = request.form.get("theme", "dark")
    if theme not in ("dark", "light"):
        abort(400)
    save_settings({"theme": theme})
    log_event("INFO", f"Dashboard theme changed to {theme}.")
    flash("Theme saved.")
    return redirect(url_for("index"))

@app.route("/request-action", methods=["POST"])
@login_required
def request_action():
    action = request.form.get("action", "")
    target = request.form.get("target", "").strip()[:200]
    value = request.form.get("value", "").strip()[:100]
    if not value:
        flash("A value is required.")
        return redirect(url_for("index"))
    if action == "group_name":
        save_settings({"group_name_target": value})
        message = f"Group-name request logged for target '{target or 'not specified'}'; requested value '{value}'. No live change performed."
    elif action == "nickname":
        save_settings({"nickname_target_id": target, "nickname_value": value})
        message = f"Nickname request logged for participant '{target or 'not specified'}'; requested value '{value}'. No live change performed."
    else:
        flash("Unknown action.")
        return redirect(url_for("index"))
    log_event("REQUEST", message)
    flash("Request added to activity log. No live Messenger change was performed.")
    return redirect(url_for("index"))

@app.route("/rules/add", methods=["POST"])
@login_required
def add_rule():
    keyword = request.form.get("keyword", "").strip()[:100]
    reply = request.form.get("reply", "").strip()[:2000]
    if not keyword or not reply:
        flash("Keyword and reply are required.")
        return redirect(url_for("index"))
    with db() as con:
        con.execute("INSERT INTO reply_rules(keyword,reply,enabled) VALUES(?,?,1)", (keyword, reply))
    log_event("INFO", f"Auto-reply rule added for keyword '{keyword}'.")
    flash("Rule saved. It is configuration only and is not connected to live Messenger messages.")
    return redirect(url_for("index"))

@app.route("/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def toggle_rule(rule_id):
    with db() as con:
        row = con.execute("SELECT enabled,keyword FROM reply_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            abort(404)
        new_enabled = 0 if row["enabled"] else 1
        con.execute("UPDATE reply_rules SET enabled=? WHERE id=?", (new_enabled, rule_id))
    log_event("INFO", f"Auto-reply rule '{row['keyword']}' {'enabled' if new_enabled else 'disabled'}.")
    flash("Rule updated.")
    return redirect(url_for("index"))

@app.route("/rules/<int:rule_id>/delete", methods=["POST"])
@login_required
def delete_rule(rule_id):
    with db() as con:
        row = con.execute("SELECT keyword FROM reply_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            abort(404)
        con.execute("DELETE FROM reply_rules WHERE id=?", (rule_id,))
    log_event("INFO", f"Auto-reply rule '{row['keyword']}' deleted.")
    flash("Rule deleted.")
    return redirect(url_for("index"))

@app.route("/command", methods=["POST"])
@login_required
def command():
    cmd = request.form.get("cmd", "")
    if cmd == "status":
        log_event("INFO", "Status command: dashboard is online; Messenger integration is not connected.")
        flash("Dashboard online. Messenger integration is not connected.")
    elif cmd == "logs":
        log_event("INFO", "Manual log entry created from command panel.")
        flash("Activity log entry created.")
    elif cmd == "reply_on":
        save_settings({"auto_reply_enabled": "1"})
        log_event("INFO", "Command enabled auto-reply configuration.")
        flash("Auto-reply configuration enabled; no messages are sent.")
    elif cmd == "reply_off":
        save_settings({"auto_reply_enabled": "0"})
        log_event("INFO", "Command disabled auto-reply configuration.")
        flash("Auto-reply configuration disabled.")
    else:
        flash("Unknown command.")
    return redirect(url_for("index"))

@app.route("/validate-cookie-json", methods=["POST"])
@login_required
def validate_cookie_json():
    raw = request.form.get("cookie_json", "")
    if len(raw) > 200000:
        flash("JSON is too large. Maximum size is 200 KB.")
        return redirect(url_for("index"))
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        log_event("INFO", "Cookie JSON validator used; invalid JSON syntax.")
        flash("Invalid JSON syntax. No contents were saved.")
        return redirect(url_for("index"))
    if isinstance(parsed, list):
        shape_ok = all(isinstance(x, dict) and isinstance(x.get("name"), str)
                       and isinstance(x.get("value"), str) for x in parsed)
    else:
        shape_ok = False
    log_event("INFO", "Cookie JSON validator used; " + ("valid list shape." if shape_ok else "unexpected shape."))
    flash("JSON syntax and basic list shape look valid." if shape_ok else
          "JSON parsed, but expected a list of objects with string name/value fields.")
    return redirect(url_for("index"))

# Ensure tables exist before the app starts serving requests.
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
