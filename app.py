import hashlib
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
ROLE_LABELS = {"admin": "Admin", "projektleiter": "Projektleiter", "bearbeiter": "Bearbeiter"}


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(stored: str, password: str) -> bool:
    if not stored.startswith("pbkdf2_sha256$"):
        return stored == password
    parts = stored.split("$", 2)
    if len(parts) != 3:
        return False
    _, salt, expected = parts
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()
    return secrets.compare_digest(expected, digest)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            first_name TEXT NOT NULL DEFAULT '',
            last_name TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'projektleiter', 'bearbeiter')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    columns = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "first_name" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN first_name TEXT NOT NULL DEFAULT ''")
    if "last_name" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN last_name TEXT NOT NULL DEFAULT ''")
    if "email" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")

    existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO users (username, email, first_name, last_name, password, role) VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", "admin@example.com", "System", "Admin", hash_password("admin123"), "admin"),
        )
    else:
        conn.execute("UPDATE users SET email = COALESCE(NULLIF(email, ''), ?) WHERE username='admin'", ("admin@example.com",))
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
    mapping = {"admin": "danger", "projektleiter": "warning text-dark", "bearbeiter": "primary"}
    return f"<span class='badge bg-{mapping.get(role, 'secondary')}'>{html.escape(ROLE_LABELS.get(role, role))}</span>"


def login_page(flash=None):
    flash_html = ""
    if flash:
        flash_html = f"<div class='alert alert-{flash.get('kind', 'info')}'>{html.escape(flash.get('msg', ''))}</div>"
    return f"""<!doctype html>
<html lang='de'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>Login</title>
  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
</head>
<body class='bg-light'>
  <div class='container py-5'>
    <div class='row justify-content-center'>
      <div class='col-md-5'>
        <div class='card shadow-sm'>
          <div class='card-body'>
            <h2 class='mb-3'>Login</h2>
            {flash_html}
            <form method='post' class='row g-3'>
              <div class='col-12'>
                <label class='form-label'>Benutzername</label>
                <input class='form-control' name='username' required>
              </div>
              <div class='col-12'>
                <label class='form-label'>Passwort</label>
                <input class='form-control' type='password' name='password' required>
              </div>
              <div class='col-12'><button class='btn btn-success w-100'>Anmelden</button></div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>"""


def layout(title, content, user, flash=None):
    user_name = html.escape(user["username"])
    full_name = f"{html.escape(user.get('first_name', ''))} {html.escape(user.get('last_name', ''))}".strip()

    flash_html = ""
    if flash:
        flash_html = f"<div class='alert alert-{flash.get('kind', 'info')}'>{html.escape(flash.get('msg', ''))}</div>"

    nav_admin_link = ""
    if user.get("role") == "admin":
        nav_admin_link = "<a class='list-group-item list-group-item-action' href='/admin/users'>Benutzerverwaltung</a>"

    left_col = f"""
    <div class='card shadow-sm'>
      <div class='card-header'>Navigation</div>
      <div class='list-group list-group-flush'>
        <a class='list-group-item list-group-item-action' href='/dashboard'>Dashboard</a>
        <a class='list-group-item list-group-item-action' href='/projects'>Projektverwaltung</a>
        {nav_admin_link}
      </div>
    </div>
    """

    right_col = f"""
    <div class='card shadow-sm'>
      <div class='card-header'>Benutzer</div>
      <div class='card-body'>
        <div><strong>{full_name or user_name}</strong></div>
        <div class='text-muted small'>{user_name}</div>
        <div>Rolle: {role_badge(user['role'])}</div>
      </div>
    </div>
    """

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
      <ul class='navbar-nav ms-auto'>
        <li class='nav-item dropdown'>
          <a class='nav-link dropdown-toggle text-light' href='#' role='button' data-bs-toggle='dropdown'>{user_name}</a>
          <ul class='dropdown-menu dropdown-menu-end'>
            <li><a class='dropdown-item' href='/account'>Mein Account</a></li>
            <li><hr class='dropdown-divider'></li>
            <li><a class='dropdown-item' href='/logout'>Abmelden</a></li>
          </ul>
        </li>
      </ul>
    </div>
  </header>
  <div class='container-fluid'>
    <div class='row g-3'>
      <aside class='col-lg-2'>{left_col}</aside>
      <main class='col-lg-8'>{flash_html}<div class='card shadow-sm'><div class='card-body'>{content}</div></div></main>
      <aside class='col-lg-2'>{right_col}</aside>
    </div>
  </div>
  <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>
</body>
</html>"""


def admin_only(start_response, user):
    page = layout(
        "Kein Zugriff",
        "<h2>Kein Zugriff</h2><p>Nur der Admin kann Benutzer anlegen, bearbeiten und löschen.</p>",
        user,
        {"kind": "danger", "msg": "Nur Admin."},
    )
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
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Not found"]

    if path == "/login":
        if method == "POST":
            form = parse_form(environ)
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute(
                "SELECT id, username, email, first_name, last_name, password, role FROM users WHERE username=?",
                (form.get("username", ""),),
            ).fetchone()
            if row and verify_password(row[5], form.get("password", "")):
                # transparently upgrade legacy plain-text password
                if not str(row[5]).startswith("pbkdf2_sha256$"):
                    conn.execute("UPDATE users SET password=? WHERE id=?", (hash_password(form.get("password", "")), row[0]))
                    conn.commit()
                conn.close()
                newsid = secrets.token_hex(16)
                SESSIONS[newsid] = {
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "first_name": row[3],
                    "last_name": row[4],
                    "role": row[6],
                }
                return redirect(start_response, "/dashboard", sid=newsid)
            conn.close()
            page = login_page({"kind": "danger", "msg": "Ungültige Zugangsdaten."})
        else:
            page = login_page()
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/logout":
        if sid in SESSIONS:
            del SESSIONS[sid]
        start_response("302 Found", [("Location", "/login"), ("Set-Cookie", "sid=; Max-Age=0; Path=/")])
        return [b""]

    if not user:
        return redirect(start_response, "/login")

    if path == "/dashboard":
        body = (
            f"<h2>Dashboard</h2><p>Willkommen <strong>{html.escape(user.get('first_name', ''))} {html.escape(user.get('last_name', ''))}</strong>.</p>"
            "<p>Benutzer werden ausschließlich durch Administratoren verwaltet.</p>"
        )
        page = layout("Dashboard", body, user)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/projects":
        body = (
            "<h2>Projektverwaltung</h2>"
            "<p class='mb-0'>Projektverwaltung ist vorbereitet. Hier können als nächstes Projekte, Status und Verantwortliche verwaltet werden.</p>"
        )
        page = layout("Projektverwaltung", body, user)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/account":
        body = (
            "<h2>Mein Account</h2>"
            f"<p><strong>Vorname:</strong> {html.escape(user.get('first_name', ''))}</p>"
            f"<p><strong>Nachname:</strong> {html.escape(user.get('last_name', ''))}</p>"
            f"<p><strong>Benutzername:</strong> {html.escape(user['username'])}</p>"
            f"<p><strong>E-Mailadresse:</strong> {html.escape(user.get('email', ''))}</p>"
            f"<p><strong>Rolle:</strong> {role_badge(user['role'])}</p>"
        )
        page = layout("Mein Account", body, user)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/admin/users":
        if user["role"] != "admin":
            return admin_only(start_response, user)

        query = parse_qs(environ.get("QUERY_STRING", ""))
        sort = query.get("sort", ["last_name"])[0]
        direction = query.get("dir", ["asc"])[0].lower()
        if sort not in {"first_name", "last_name", "username", "email", "role"}:
            sort = "last_name"
        if direction not in {"asc", "desc"}:
            direction = "asc"

        conn = sqlite3.connect(DB_PATH)
        flash = None
        if method == "POST":
            form = parse_form(environ)
            if form.get("action") == "delete":
                uid = form.get("user_id", "")
                if uid.isdigit() and str(user["id"]) != uid:
                    target = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
                    if target:
                        conn.execute("DELETE FROM users WHERE id=?", (uid,))
                        conn.commit()
                        flash = {"kind": "success", "msg": f"Benutzer {target[0]} gelöscht."}

        users = conn.execute(
            f"SELECT id, first_name, last_name, username, email, role FROM users ORDER BY {sort} {direction.upper()}, id ASC"
        ).fetchall()
        conn.close()

        rows = []
        for uid, first_name, last_name, uname, email, role in users:
            rows.append(
                "<tr>"
                f"<td>{html.escape(first_name)}</td>"
                f"<td>{html.escape(last_name)}</td>"
                f"<td>{html.escape(uname)}</td>"
                f"<td>{html.escape(email)}</td>"
                f"<td>{role_badge(role)}</td>"
                "<td><div class='d-flex gap-2'>"
                f"<a class='btn btn-sm btn-outline-secondary' href='/admin/users/{uid}'>Bearbeiten</a>"
                "<form method='post'>"
                "<input type='hidden' name='action' value='delete'>"
                f"<input type='hidden' name='user_id' value='{uid}'>"
                "<button class='btn btn-sm btn-outline-danger'>Löschen</button>"
                "</form></div></td>"
                "</tr>"
            )

        headers = []
        for col, label in (("first_name", "Vorname"), ("last_name", "Nachname"), ("username", "Benutzername"), ("email", "E-Mailadresse"), ("role", "Rolle")):
            next_dir = "desc" if (sort == col and direction == "asc") else "asc"
            arrow = ""
            if sort == col:
                arrow = " ▲" if direction == "asc" else " ▼"
            headers.append(f"<th><a class='link-dark text-decoration-none' href='/admin/users?sort={col}&dir={next_dir}'>{label}{arrow}</a></th>")

        body = (
            "<div class='d-flex justify-content-between align-items-center mb-3'>"
            "<h2 class='mb-0'>Benutzerverwaltung</h2>"
            "<a class='btn btn-success' href='/admin/users/new'>Neuen Benutzer anlegen</a>"
            "</div>"
            "<div class='table-responsive'><table class='table table-striped align-middle'>"
            f"<thead><tr>{''.join(headers)}<th>Aktionen</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )
        page = layout("Benutzerverwaltung", body, user, flash)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/admin/users/new":
        if user["role"] != "admin":
            return admin_only(start_response, user)

        conn = sqlite3.connect(DB_PATH)
        if method == "POST":
            form = parse_form(environ)
            first_name = form.get("first_name", "").strip()
            last_name = form.get("last_name", "").strip()
            username = form.get("username", "").strip()
            email = form.get("email", "").strip()
            password = form.get("password", "")
            role = form.get("role", "bearbeiter")
            if role not in ROLES:
                role = "bearbeiter"
            exists_user = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            exists_email = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()

            if len(username) < 3 or "@" not in email or len(password) < 6:
                flash = {"kind": "warning", "msg": "Benutzername >=3, gültige E-Mailadresse und Passwort >=6 erforderlich."}
            elif exists_user:
                flash = {"kind": "danger", "msg": "Benutzername bereits vergeben."}
            elif exists_email:
                flash = {"kind": "danger", "msg": "E-Mailadresse bereits vergeben."}
            else:
                conn.execute(
                    "INSERT INTO users (first_name, last_name, username, email, password, role) VALUES (?, ?, ?, ?, ?, ?)",
                    (first_name, last_name, username, email, hash_password(password), role),
                )
                conn.commit()
                conn.close()
                return redirect(start_response, "/admin/users")
        else:
            flash = None
        conn.close()

        options = "".join([f"<option value='{r}'>{ROLE_LABELS.get(r, r)}</option>" for r in ROLES])
        body = (
            "<h2>Neuen Benutzer anlegen</h2>"
            "<form method='post' class='row g-3'>"
            "<div class='col-md-6'><label class='form-label'>Vorname</label><input class='form-control' name='first_name'></div>"
            "<div class='col-md-6'><label class='form-label'>Nachname</label><input class='form-control' name='last_name'></div>"
            "<div class='col-md-6'><label class='form-label'>Benutzername</label><input class='form-control' name='username' required></div>"
            "<div class='col-md-6'><label class='form-label'>E-Mailadresse</label><input class='form-control' name='email' type='email' required></div>"
            "<div class='col-md-6'><label class='form-label'>Passwort</label><input class='form-control' type='password' name='password' required minlength='6'></div>"
            f"<div class='col-md-6'><label class='form-label'>Rolle</label><select class='form-select' name='role'>{options}</select></div>"
            "<div class='col-12 d-flex gap-2'><button class='btn btn-success'>Speichern</button><a class='btn btn-outline-secondary' href='/admin/users'>Zurück</a></div>"
            "</form>"
        )
        page = layout("Benutzer anlegen", body, user, flash)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path.startswith("/admin/users/"):
        if user["role"] != "admin":
            return admin_only(start_response, user)

        uid = path.split("/")[-1]
        if not uid.isdigit():
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Not found"]

        conn = sqlite3.connect(DB_PATH)
        target = conn.execute(
            "SELECT id, first_name, last_name, username, email, role, created_at FROM users WHERE id=?",
            (uid,),
        ).fetchone()
        if not target:
            conn.close()
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Not found"]

        flash = None
        if method == "POST":
            form = parse_form(environ)
            action = form.get("action", "save")
            if action == "delete":
                if str(user["id"]) == uid:
                    flash = {"kind": "warning", "msg": "Du kannst dich nicht selbst löschen."}
                else:
                    conn.execute("DELETE FROM users WHERE id=?", (uid,))
                    conn.commit()
                    conn.close()
                    return redirect(start_response, "/admin/users")
            else:
                first_name = form.get("first_name", "").strip()
                last_name = form.get("last_name", "").strip()
                username = form.get("username", "").strip()
                email = form.get("email", "").strip()
                role = form.get("role", target[5])
                password = form.get("password", "")
                if role not in ROLES:
                    role = target[5]

                existing_name = conn.execute("SELECT id FROM users WHERE username=? AND id != ?", (username, uid)).fetchone()
                existing_email = conn.execute("SELECT id FROM users WHERE email=? AND id != ?", (email, uid)).fetchone()

                if len(username) < 3 or "@" not in email:
                    flash = {"kind": "warning", "msg": "Benutzername >=3 und gültige E-Mailadresse erforderlich."}
                elif existing_name:
                    flash = {"kind": "danger", "msg": "Benutzername bereits vergeben."}
                elif existing_email:
                    flash = {"kind": "danger", "msg": "E-Mailadresse bereits vergeben."}
                elif password and len(password) < 6:
                    flash = {"kind": "warning", "msg": "Neues Passwort muss mindestens 6 Zeichen haben."}
                else:
                    if password:
                        conn.execute(
                            "UPDATE users SET first_name=?, last_name=?, username=?, email=?, role=?, password=? WHERE id=?",
                            (first_name, last_name, username, email, role, hash_password(password), uid),
                        )
                    else:
                        conn.execute(
                            "UPDATE users SET first_name=?, last_name=?, username=?, email=?, role=? WHERE id=?",
                            (first_name, last_name, username, email, role, uid),
                        )
                    conn.commit()
                    flash = {"kind": "success", "msg": "Benutzer gespeichert."}

            target = conn.execute(
                "SELECT id, first_name, last_name, username, email, role, created_at FROM users WHERE id=?",
                (uid,),
            ).fetchone()

        conn.close()
        options = "".join([f"<option value='{r}' {'selected' if r == target[5] else ''}>{ROLE_LABELS.get(r, r)}</option>" for r in ROLES])
        body = (
            "<h2>Benutzerdetails</h2>"
            "<form method='post' class='row g-3'>"
            "<input type='hidden' name='action' value='save'>"
            f"<div class='col-md-6'><label class='form-label'>Vorname</label><input class='form-control' name='first_name' value='{html.escape(target[1])}'></div>"
            f"<div class='col-md-6'><label class='form-label'>Nachname</label><input class='form-control' name='last_name' value='{html.escape(target[2])}'></div>"
            f"<div class='col-md-6'><label class='form-label'>Benutzername</label><input class='form-control' name='username' value='{html.escape(target[3])}' required></div>"
            f"<div class='col-md-6'><label class='form-label'>E-Mailadresse</label><input class='form-control' name='email' type='email' value='{html.escape(target[4])}' required></div>"
            f"<div class='col-md-6'><label class='form-label'>Rolle</label><select class='form-select' name='role'>{options}</select></div>"
            "<div class='col-md-6'><label class='form-label'>Neues Passwort (optional)</label><input class='form-control' type='password' name='password'></div>"
            f"<div class='col-md-6'><label class='form-label'>Erstellt</label><input class='form-control' value='{html.escape(target[6])}' disabled></div>"
            "<div class='col-12 d-flex gap-2'>"
            "<button class='btn btn-primary'>Speichern</button>"
            "</form>"
            "<form method='post'><input type='hidden' name='action' value='delete'><button class='btn btn-danger'>Löschen</button></form>"
            "<a class='btn btn-outline-secondary' href='/admin/users'>Zurück</a>"
            "</div>"
        )
        page = layout("Benutzerdetails", body, user, flash)
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
