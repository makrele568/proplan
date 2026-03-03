import html
import os
import secrets
import sqlite3
from http import cookies
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "proplan.sqlite"))
SESSIONS = {}
ROLES = ("admin", "projektleiter", "bearbeiter")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'projektleiter', 'bearbeiter')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "admin123", "admin"))
    conn.commit()
    conn.close()


def parse_cookies(environ):
    raw = environ.get("HTTP_COOKIE", "")
    c = cookies.SimpleCookie()
    c.load(raw)
    return {k: morsel.value for k, morsel in c.items()}


def parse_form(environ):
    try:
        size = int(environ.get("CONTENT_LENGTH", "0"))
    except ValueError:
        size = 0
    data = environ["wsgi.input"].read(size).decode("utf-8")
    form = parse_qs(data)
    return {k: v[0] for k, v in form.items()}


def redirect(start_response, location, sid=None):
    headers = [("Location", location)]
    if sid:
        headers.append(("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"))
    start_response("302 Found", headers)
    return [b""]


def role_badge(role):
    mapping = {
        "admin": "danger",
        "projektleiter": "warning text-dark",
        "bearbeiter": "primary",
    }
    return f"<span class='badge bg-{mapping.get(role, 'secondary')}'>{html.escape(role)}</span>"


def layout(title, content, user=None, flash=None):
    nav_links = ""
    if user:
        uname = html.escape(user['username'])
        nav_links += (
            "<li class='nav-item dropdown'>"
            f"<a class='nav-link dropdown-toggle text-light' href='#' role='button' data-bs-toggle='dropdown' aria-expanded='false'>{uname}</a>"
            "<ul class='dropdown-menu dropdown-menu-end'>"
            "<li><a class='dropdown-item' href='/account'>Mein Account</a></li>"
            "<li><hr class='dropdown-divider'></li>"
            "<li><a class='dropdown-item' href='/logout'>Abmelden</a></li>"
            "</ul></li>"
        )
    else:
        nav_links += "<li class='nav-item'><a class='nav-link text-light' href='/login'>Login</a></li>"
        nav_links += "<li class='nav-item'><a class='nav-link text-light' href='/register'>Registrieren</a></li>"

    user_panel = "<p class='text-muted mb-0'>Nicht angemeldet</p>"
    if user:
        user_panel = (
            f"<div><strong>{html.escape(user['username'])}</strong></div>"
            f"<div>Rolle: {role_badge(user['role'])}</div>"
        )

    left_col = """
    <div class='card shadow-sm'>
      <div class='card-header'>Navigation</div>
      <div class='list-group list-group-flush'>
        <a class='list-group-item list-group-item-action' href='/login'>Loginseite</a>
        <a class='list-group-item list-group-item-action' href='/dashboard'>Dashboard</a>
        <a class='list-group-item list-group-item-action' href='/admin/users'>Benutzerverwaltung</a>
      </div>
    </div>
    """

    right_col = f"""
    <div class='card shadow-sm'>
      <div class='card-header'>Benutzer</div>
      <div class='card-body'>{user_panel}</div>
    </div>
    """

    flash_html = ""
    if flash:
        kind = flash.get("kind", "info")
        msg = html.escape(flash.get("msg", ""))
        flash_html = f"<div class='alert alert-{kind}' role='alert'>{msg}</div>"

    return f"""<!doctype html>
<html lang='de'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>{html.escape(title)}</title>
  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
</head>
<body class='bg-light'>
  <header class='navbar navbar-expand-lg navbar-dark bg-dark mb-3'>
    <div class='container-fluid'>
      <a class='navbar-brand' href='/dashboard'>ProPlan</a>
      <span class='navbar-text text-white me-3'>WebApp mit Benutzerverwaltung</span>
      <ul class='navbar-nav ms-auto'>{nav_links}</ul>
    </div>
  </header>

  <div class='container-fluid'>
    <div class='row g-3'>
      <aside class='col-lg-2'>{left_col}</aside>
      <main class='col-lg-8'>
        {flash_html}
        <div class='card shadow-sm'>
          <div class='card-body'>{content}</div>
        </div>
      </main>
      <aside class='col-lg-2'>{right_col}</aside>
    </div>
  </div>
  <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>
</body>
</html>"""


def unauthorized_page(start_response, user):
    page = layout("Kein Zugriff", "<h2>Kein Zugriff</h2><p>Du hast keine Berechtigung für diesen Bereich.</p>", user, {"kind": "danger", "msg": "Nur Admin oder Projektleiter."})
    start_response("403 Forbidden", [("Content-Type", "text/html; charset=utf-8")])
    return [page.encode()]


def app(environ, start_response):
    init_db()
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    sid = parse_cookies(environ).get("sid")
    user = SESSIONS.get(sid)

    if path == "/":
        return redirect(start_response, "/login")

    if path == "/register":
        if method == "POST":
            form = parse_form(environ)
            username = form.get("username", "").strip()
            password = form.get("password", "")
            role = form.get("role", "bearbeiter")
            if role not in ROLES:
                role = "bearbeiter"

            conn = sqlite3.connect(DB_PATH)
            exists = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if len(username) < 3 or len(password) < 6:
                msg = "Benutzername >= 3 und Passwort >= 6 Zeichen erforderlich."
                kind = "warning"
            elif exists:
                msg = "Benutzername ist bereits vergeben."
                kind = "danger"
            else:
                conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
                conn.commit()
                conn.close()
                return redirect(start_response, "/login")
            conn.close()
        else:
            msg = None
            kind = "info"

        role_options = "".join([f"<option value='{r}' {'selected' if r=='bearbeiter' else ''}>{r}</option>" for r in ROLES])
        body = f"""
        <h2 class='mb-3'>Registrieren</h2>
        <form method='post' class='row g-3'>
          <div class='col-md-6'>
            <label class='form-label'>Benutzername</label>
            <input class='form-control' name='username' required minlength='3'>
          </div>
          <div class='col-md-6'>
            <label class='form-label'>Passwort</label>
            <input class='form-control' type='password' name='password' required minlength='6'>
          </div>
          <div class='col-md-6'>
            <label class='form-label'>Rolle</label>
            <select class='form-select' name='role'>{role_options}</select>
          </div>
          <div class='col-12'><button class='btn btn-primary'>Registrieren</button></div>
        </form>
        """
        page = layout("Registrieren", body, user, {"kind": kind, "msg": msg} if msg else None)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/login":
        if method == "POST":
            form = parse_form(environ)
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute(
                "SELECT id, username, role FROM users WHERE username=? AND password=?",
                (form.get("username", ""), form.get("password", "")),
            ).fetchone()
            conn.close()
            if row:
                newsid = secrets.token_hex(16)
                SESSIONS[newsid] = {"id": row[0], "username": row[1], "role": row[2]}
                return redirect(start_response, "/dashboard", sid=newsid)
            flash = {"kind": "danger", "msg": "Ungültige Zugangsdaten."}
        else:
            flash = None

        body = """
        <h2 class='mb-3'>Login</h2>
        <form method='post' class='row g-3'>
          <div class='col-md-6'>
            <label class='form-label'>Benutzername</label>
            <input class='form-control' name='username' required>
          </div>
          <div class='col-md-6'>
            <label class='form-label'>Passwort</label>
            <input class='form-control' type='password' name='password' required>
          </div>
          <div class='col-12'><button class='btn btn-success'>Anmelden</button></div>
        </form>
        """
        page = layout("Login", body, user, flash)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]


    if path == "/account":
        if not user:
            return redirect(start_response, "/login")
        body = (
            "<h2>Mein Account</h2>"
            f"<p><strong>Benutzername:</strong> {html.escape(user['username'])}</p>"
            f"<p><strong>Rolle:</strong> {role_badge(user['role'])}</p>"
            "<p class='text-muted'>Account-Details können hier erweitert werden.</p>"
        )
        page = layout("Mein Account", body, user)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/logout":
        if sid in SESSIONS:
            del SESSIONS[sid]
        start_response("302 Found", [("Location", "/login"), ("Set-Cookie", "sid=; Max-Age=0; Path=/")])
        return [b""]

    if path == "/dashboard":
        if not user:
            return redirect(start_response, "/login")
        hints = {
            "admin": "Du kannst alle Benutzer und Rollen verwalten.",
            "projektleiter": "Du kannst Benutzer sehen und Bearbeiter verwalten.",
            "bearbeiter": "Du hast nur lesenden Zugriff auf dein Dashboard.",
        }
        body = (
            f"<h2>Dashboard</h2><p>Willkommen <strong>{html.escape(user['username'])}</strong>.</p>"
            f"<p>{html.escape(hints.get(user['role'], ''))}</p>"
        )
        page = layout("Dashboard", body, user)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/admin/users":
        if not user:
            return redirect(start_response, "/login")
        if user["role"] not in {"admin", "projektleiter"}:
            return unauthorized_page(start_response, user)

        conn = sqlite3.connect(DB_PATH)
        flash = None

        if method == "POST":
            form = parse_form(environ)
            action = form.get("action")
            if action == "create_user":
                new_username = form.get("username", "").strip()
                new_password = form.get("password", "")
                new_role = form.get("role", "bearbeiter")
                if new_role not in ROLES:
                    new_role = "bearbeiter"
                exists = conn.execute("SELECT id FROM users WHERE username=?", (new_username,)).fetchone()
                if len(new_username) < 3 or len(new_password) < 6:
                    flash = {"kind": "warning", "msg": "Neuer Benutzer: Username >=3, Passwort >=6."}
                elif exists:
                    flash = {"kind": "danger", "msg": "Neuer Benutzer konnte nicht angelegt werden: Name bereits vergeben."}
                elif user["role"] == "projektleiter" and new_role == "admin":
                    flash = {"kind": "danger", "msg": "Projektleiter dürfen keine Admins anlegen."}
                else:
                    conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (new_username, new_password, new_role))
                    conn.commit()
                    flash = {"kind": "success", "msg": f"Benutzer {new_username} wurde angelegt."}

            uid = form.get("user_id")
            if uid and uid.isdigit():
                target = conn.execute("SELECT id, role, username FROM users WHERE id=?", (uid,)).fetchone()
                if target:
                    if action == "change_role":
                        new_role = form.get("role")
                        if new_role not in ROLES:
                            flash = {"kind": "warning", "msg": "Ungültige Rolle."}
                        elif user["role"] == "projektleiter" and new_role == "admin":
                            flash = {"kind": "danger", "msg": "Projektleiter dürfen keine Admin-Rolle vergeben."}
                        elif user["role"] == "projektleiter" and target[1] == "admin":
                            flash = {"kind": "danger", "msg": "Projektleiter dürfen Admins nicht ändern."}
                        else:
                            conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
                            conn.commit()
                            flash = {"kind": "success", "msg": f"Rolle für {target[2]} aktualisiert."}
                    elif action == "delete":
                        if str(user["id"]) == str(uid):
                            flash = {"kind": "warning", "msg": "Du kannst dich nicht selbst löschen."}
                        elif user["role"] == "projektleiter" and target[1] == "admin":
                            flash = {"kind": "danger", "msg": "Projektleiter dürfen keine Admins löschen."}
                        else:
                            conn.execute("DELETE FROM users WHERE id=?", (uid,))
                            conn.commit()
                            flash = {"kind": "success", "msg": f"Benutzer {target[2]} gelöscht."}

        users = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC").fetchall()
        conn.close()

        rows = []
        for uid, uname, role, created in users:
            opts = "".join(
                [f"<option value='{r}' {'selected' if r==role else ''}>{r}</option>" for r in ROLES]
            )
            rows.append(
                "<tr>"
                f"<td>{uid}</td><td>{html.escape(uname)}</td><td>{role_badge(role)}</td><td>{html.escape(created)}</td>"
                "<td>"
                "<div class='d-flex gap-2 flex-wrap'>"
                "<form method='post' class='d-flex gap-2'>"
                "<input type='hidden' name='action' value='change_role'>"
                f"<input type='hidden' name='user_id' value='{uid}'>"
                f"<select class='form-select form-select-sm' name='role'>{opts}</select>"
                "<button class='btn btn-sm btn-outline-primary'>Speichern</button>"
                "</form>"
                "<form method='post'>"
                "<input type='hidden' name='action' value='delete'>"
                f"<input type='hidden' name='user_id' value='{uid}'>"
                "<button class='btn btn-sm btn-outline-danger'>Löschen</button>"
                "</form>"
                "</div>"
                "</td></tr>"
            )

        create_opts = "".join([f"<option value='{r}'>{r}</option>" for r in ROLES])
        body = (
            "<h2 class='mb-3'>Benutzerverwaltung</h2>"
            "<div class='card mb-3'><div class='card-header'>Neuen Benutzer hinzufügen</div><div class='card-body'>"
            "<form method='post' class='row g-2 align-items-end'>"
            "<input type='hidden' name='action' value='create_user'>"
            "<div class='col-md-4'><label class='form-label'>Benutzername</label><input class='form-control' name='username' minlength='3' required></div>"
            "<div class='col-md-4'><label class='form-label'>Passwort</label><input class='form-control' name='password' minlength='6' required></div>"
            f"<div class='col-md-2'><label class='form-label'>Rolle</label><select class='form-select' name='role'>{create_opts}</select></div>"
            "<div class='col-md-2'><button class='btn btn-success w-100'>Anlegen</button></div>"
            "</form></div></div>"
            "<div class='table-responsive'><table class='table table-striped align-middle'>"
            "<thead><tr><th>ID</th><th>Benutzername</th><th>Rolle</th><th>Erstellt</th><th>Aktionen</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )
        page = layout("Benutzerverwaltung", body, user, flash)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return [b"Not found"]


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5050"))
    with make_server("0.0.0.0", port, app) as server:
        print(f"Server läuft auf http://0.0.0.0:{port}")
        server.serve_forever()
