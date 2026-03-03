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


def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = db_connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL DEFAULT '',
            last_name TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'projektleiter', 'bearbeiter')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_number TEXT UNIQUE NOT NULL,
            project_name TEXT NOT NULL,
            project_address TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS project_editors (
            project_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (project_id, user_id),
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS project_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            address TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS project_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        """
    )

    user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "email" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")

    admin = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (username, email, first_name, last_name, password, role) VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", "admin@example.com", "System", "Admin", hash_password("admin123"), "admin"),
        )
    else:
        conn.execute("UPDATE users SET email = COALESCE(NULLIF(email, ''), ?) WHERE username='admin'", ("admin@example.com",))
    conn.commit()
    conn.close()


def parse_cookies(environ):
    c = cookies.SimpleCookie()
    c.load(environ.get("HTTP_COOKIE", ""))
    return {k: m.value for k, m in c.items()}


def parse_form(environ):
    try:
        size = int(environ.get("CONTENT_LENGTH", "0"))
    except ValueError:
        size = 0
    raw = environ["wsgi.input"].read(size).decode("utf-8")
    parsed = parse_qs(raw)
    return {k: v[0] for k, v in parsed.items()}


def redirect(start_response, location, sid=None):
    headers = [("Location", location)]
    if sid:
        headers.append(("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"))
    start_response("302 Found", headers)
    return [b""]


def role_badge(role):
    style = {"admin": "danger", "projektleiter": "warning text-dark", "bearbeiter": "primary"}.get(role, "secondary")
    return f"<span class='badge bg-{style}'>{html.escape(ROLE_LABELS.get(role, role))}</span>"


def login_page(flash=None):
    flash_html = f"<div class='alert alert-{flash['kind']}'>{html.escape(flash['msg'])}</div>" if flash else ""
    return f"""<!doctype html><html lang='de'><head>
    <meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>Login</title><link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
    </head><body class='bg-light'>
    <div class='container py-5'><div class='row justify-content-center'><div class='col-md-5'><div class='card shadow-sm'><div class='card-body'>
      <h2 class='mb-3'>Login</h2>{flash_html}
      <form method='post' class='row g-3'>
        <div class='col-12'><label class='form-label'>Benutzername</label><input class='form-control' name='username' required></div>
        <div class='col-12'><label class='form-label'>Passwort</label><input class='form-control' type='password' name='password' required></div>
        <div class='col-12'><button class='btn btn-success w-100'>Anmelden</button></div>
      </form>
    </div></div></div></div></div></body></html>"""


def layout(title, content, user, flash=None):
    nav_admin = "<a class='list-group-item list-group-item-action' href='/admin/users'>Benutzerverwaltung</a>" if user["role"] == "admin" else ""
    flash_html = f"<div class='alert alert-{flash['kind']}'>{html.escape(flash['msg'])}</div>" if flash else ""
    fullname = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or user["username"]
    return f"""<!doctype html><html lang='de'><head>
    <meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>{html.escape(title)}</title><link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
    </head><body class='bg-light'>
    <header class='navbar navbar-expand-lg navbar-dark bg-dark mb-3'><div class='container-fluid'>
      <a class='navbar-brand' href='/dashboard'>ProPlan</a>
      <ul class='navbar-nav ms-auto'><li class='nav-item dropdown'>
        <a class='nav-link dropdown-toggle text-light' href='#' role='button' data-bs-toggle='dropdown'>{html.escape(user['username'])}</a>
        <ul class='dropdown-menu dropdown-menu-end'>
          <li><a class='dropdown-item' href='/account'>Mein Account</a></li><li><hr class='dropdown-divider'></li>
          <li><a class='dropdown-item' href='/logout'>Abmelden</a></li>
        </ul>
      </li></ul>
    </div></header>
    <div class='container-fluid'><div class='row g-3'>
      <aside class='col-lg-2'><div class='card shadow-sm'><div class='card-header'>Navigation</div><div class='list-group list-group-flush'>
        <a class='list-group-item list-group-item-action' href='/dashboard'>Dashboard</a>
        <a class='list-group-item list-group-item-action' href='/projects'>Projektverwaltung</a>
        {nav_admin}
      </div></div></aside>
      <main class='col-lg-8'>{flash_html}<div class='card shadow-sm'><div class='card-body'>{content}</div></div></main>
      <aside class='col-lg-2'><div class='card shadow-sm'><div class='card-header'>Benutzer</div><div class='card-body'>
        <div><strong>{html.escape(fullname)}</strong></div><div class='text-muted small'>{html.escape(user['username'])}</div><div>Rolle: {role_badge(user['role'])}</div>
      </div></div></aside>
    </div></div>
    <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>
    </body></html>"""


def forbid(start_response, user, message):
    page = layout("Kein Zugriff", f"<h2>Kein Zugriff</h2><p>{html.escape(message)}</p>", user, {"kind": "danger", "msg": "Keine Berechtigung."})
    start_response("403 Forbidden", [("Content-Type", "text/html; charset=utf-8")])
    return [page.encode()]


def get_current_user(environ):
    sid = parse_cookies(environ).get("sid")
    return SESSIONS.get(sid), sid


def app(environ, start_response):
    init_db()
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    user, sid = get_current_user(environ)

    if path == "/":
        return redirect(start_response, "/login")

    if path == "/register":
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Not found"]

    if path == "/login":
        if method == "POST":
            form = parse_form(environ)
            conn = db_connect()
            row = conn.execute("SELECT * FROM users WHERE username=?", (form.get("username", ""),)).fetchone()
            if row and verify_password(row["password"], form.get("password", "")):
                if not row["password"].startswith("pbkdf2_sha256$"):
                    conn.execute("UPDATE users SET password=? WHERE id=?", (hash_password(form.get("password", "")), row["id"]))
                    conn.commit()
                conn.close()
                newsid = secrets.token_hex(16)
                SESSIONS[newsid] = dict(row)
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
        conn = db_connect()
        projects = conn.execute(
            """
            SELECT DISTINCT p.id, p.project_number, p.project_name, p.project_address
            FROM projects p
            LEFT JOIN project_editors pe ON pe.project_id = p.id
            WHERE p.created_by = ? OR pe.user_id = ?
            ORDER BY p.id DESC
            """,
            (user["id"], user["id"]),
        ).fetchall()
        conn.close()
        items = "".join(
            [
                "<li class='list-group-item d-flex justify-content-between align-items-center'>"
                f"<span><strong>{html.escape(p['project_number'])}</strong> – {html.escape(p['project_name'])} <span class='text-muted'>({html.escape(p['project_address'])})</span></span>"
                f"<a class='btn btn-sm btn-outline-secondary' href='/projects/{p['id']}'>Details</a>"
                "</li>"
                for p in projects
            ]
        )
        if not items:
            items = "<li class='list-group-item text-muted'>Keine zugewiesenen Projekte.</li>"
        body = (
            f"<h2>Dashboard</h2><p>Willkommen <strong>{html.escape(user.get('first_name', ''))} {html.escape(user.get('last_name', ''))}</strong>.</p>"
            "<h3 class='h5 mt-4'>Meine berechtigten Projekte</h3><ul class='list-group'>"
            f"{items}</ul>"
        )
        page = layout("Dashboard", body, user)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/projects":
        conn = db_connect()
        projects = conn.execute(
            """
            SELECT p.id, p.project_number, p.project_name, p.project_address, p.created_at, p.created_by, u.username owner
            FROM projects p JOIN users u ON u.id = p.created_by
            ORDER BY p.id DESC
            """
        ).fetchall()
        conn.close()
        rows = []
        for p in projects:
            action = "<span class='text-muted'>Nur Besitzer</span>"
            if p["created_by"] == user["id"]:
                action = f"<a class='btn btn-sm btn-outline-secondary' href='/projects/{p['id']}'>Bearbeiten</a>"
            rows.append(
                "<tr>"
                f"<td>{html.escape(p['project_number'])}</td><td>{html.escape(p['project_name'])}</td><td>{html.escape(p['project_address'])}</td>"
                f"<td>{html.escape(p['owner'])}</td><td>{html.escape(p['created_at'])}</td><td>{action}</td>"
                "</tr>"
            )
        body = (
            "<div class='d-flex justify-content-between align-items-center mb-3'><h2 class='mb-0'>Projektverwaltung</h2>"
            "<a class='btn btn-success' href='/projects/new'>Neues Projekt anlegen</a></div>"
            "<div class='table-responsive'><table class='table table-striped align-middle'>"
            "<thead><tr><th>Projektnummer</th><th>Projektname</th><th>Projektadresse</th><th>Besitzer</th><th>Erstellt</th><th>Aktionen</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )
        page = layout("Projektverwaltung", body, user)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/projects/new":
        conn = db_connect()
        if method == "POST":
            form = parse_form(environ)
            pnum = form.get("project_number", "").strip()
            pname = form.get("project_name", "").strip()
            paddr = form.get("project_address", "").strip()
            exists = conn.execute("SELECT id FROM projects WHERE project_number=?", (pnum,)).fetchone()
            if len(pnum) < 2 or len(pname) < 2 or len(paddr) < 5:
                flash = {"kind": "warning", "msg": "Bitte gültige Projektdaten eingeben."}
            elif exists:
                flash = {"kind": "danger", "msg": "Projektnummer bereits vergeben."}
            else:
                conn.execute("INSERT INTO projects (project_number, project_name, project_address, created_by) VALUES (?, ?, ?, ?)", (pnum, pname, paddr, user["id"]))
                conn.commit()
                conn.close()
                return redirect(start_response, "/projects")
        else:
            flash = None
        conn.close()
        body = (
            "<h2>Neues Projekt anlegen</h2><form method='post' class='row g-3'>"
            "<div class='col-md-4'><label class='form-label'>Projektnummer</label><input class='form-control' name='project_number' required></div>"
            "<div class='col-md-4'><label class='form-label'>Projektname</label><input class='form-control' name='project_name' required></div>"
            "<div class='col-md-4'><label class='form-label'>Projektadresse</label><input class='form-control' name='project_address' required></div>"
            "<div class='col-12 d-flex gap-2'><button class='btn btn-success'>Speichern</button><a class='btn btn-outline-secondary' href='/projects'>Zurück</a></div></form>"
        )
        page = layout("Projekt anlegen", body, user, flash)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path.startswith("/projects/"):
        pid = path.split("/")[-1]
        if not pid.isdigit():
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Not found"]
        conn = db_connect()
        project = conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
        if not project:
            conn.close()
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Not found"]
        if project["created_by"] != user["id"]:
            conn.close()
            return forbid(start_response, user, "Nur der Besitzer des Projekts kann das Projekt bearbeiten oder löschen.")

        flash = None
        if method == "POST":
            form = parse_form(environ)
            action = form.get("action", "save")
            if action == "delete":
                conn.execute("DELETE FROM projects WHERE id=?", (pid,))
                conn.commit()
                conn.close()
                return redirect(start_response, "/projects")
            elif action == "save":
                pnum = form.get("project_number", "").strip()
                pname = form.get("project_name", "").strip()
                paddr = form.get("project_address", "").strip()
                new_owner = form.get("owner_user_id", str(user["id"]))
                duplicate = conn.execute("SELECT id FROM projects WHERE project_number=? AND id != ?", (pnum, pid)).fetchone()
                owner_exists = conn.execute("SELECT id FROM users WHERE id=?", (new_owner,)).fetchone() if new_owner.isdigit() else None
                if len(pnum) < 2 or len(pname) < 2 or len(paddr) < 5:
                    flash = {"kind": "warning", "msg": "Bitte gültige Projektdaten eingeben."}
                elif duplicate:
                    flash = {"kind": "danger", "msg": "Projektnummer bereits vergeben."}
                elif not owner_exists:
                    flash = {"kind": "danger", "msg": "Ungültiger Projektbesitzer."}
                else:
                    conn.execute(
                        "UPDATE projects SET project_number=?, project_name=?, project_address=?, created_by=? WHERE id=?",
                        (pnum, pname, paddr, new_owner, pid),
                    )
                    conn.commit()
                    flash = {"kind": "success", "msg": "Projekt gespeichert."}
            elif action == "add_editor":
                editor_id = form.get("editor_user_id", "")
                if editor_id.isdigit() and int(editor_id) != user["id"]:
                    conn.execute("INSERT OR IGNORE INTO project_editors (project_id, user_id) VALUES (?, ?)", (pid, editor_id))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Bearbeiter zugeordnet."}
            elif action == "remove_editor":
                editor_id = form.get("editor_user_id", "")
                if editor_id.isdigit():
                    conn.execute("DELETE FROM project_editors WHERE project_id=? AND user_id=?", (pid, editor_id))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Bearbeiter entfernt."}
            elif action == "add_address":
                title = form.get("title", "").strip()
                address = form.get("address", "").strip()
                if len(title) < 2 or len(address) < 5:
                    flash = {"kind": "warning", "msg": "Adresse konnte nicht angelegt werden."}
                else:
                    conn.execute("INSERT INTO project_addresses (project_id, title, address) VALUES (?, ?, ?)", (pid, title, address))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Adresse angelegt."}
            elif action == "edit_address":
                aid = form.get("address_id", "")
                title = form.get("title", "").strip()
                address = form.get("address", "").strip()
                if aid.isdigit() and len(title) >= 2 and len(address) >= 5:
                    conn.execute("UPDATE project_addresses SET title=?, address=? WHERE id=? AND project_id=?", (title, address, aid, pid))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Adresse gespeichert."}
            elif action == "delete_address":
                aid = form.get("address_id", "")
                if aid.isdigit():
                    conn.execute("DELETE FROM project_addresses WHERE id=? AND project_id=?", (aid, pid))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Adresse gelöscht."}
            elif action == "add_plan":
                title = form.get("title", "").strip()
                content = form.get("content", "").strip()
                if len(title) < 2 or len(content) < 2:
                    flash = {"kind": "warning", "msg": "Plan konnte nicht angelegt werden."}
                else:
                    conn.execute("INSERT INTO project_plans (project_id, title, content) VALUES (?, ?, ?)", (pid, title, content))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Plan angelegt."}
            elif action == "edit_plan":
                plid = form.get("plan_id", "")
                title = form.get("title", "").strip()
                content = form.get("content", "").strip()
                if plid.isdigit() and len(title) >= 2 and len(content) >= 2:
                    conn.execute("UPDATE project_plans SET title=?, content=? WHERE id=? AND project_id=?", (title, content, plid, pid))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Plan gespeichert."}
            elif action == "delete_plan":
                plid = form.get("plan_id", "")
                if plid.isdigit():
                    conn.execute("DELETE FROM project_plans WHERE id=? AND project_id=?", (plid, pid))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Plan gelöscht."}

            project = conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()

        users = conn.execute("SELECT id, username, first_name, last_name FROM users ORDER BY username").fetchall()
        assigned = conn.execute(
            "SELECT u.id, u.username, u.first_name, u.last_name FROM project_editors pe JOIN users u ON u.id=pe.user_id WHERE pe.project_id=? ORDER BY u.username",
            (pid,),
        ).fetchall()
        available = conn.execute(
            "SELECT id, username, first_name, last_name FROM users WHERE id != ? AND id NOT IN (SELECT user_id FROM project_editors WHERE project_id=?) ORDER BY username",
            (user["id"], pid),
        ).fetchall()
        addresses = conn.execute("SELECT id, title, address FROM project_addresses WHERE project_id=? ORDER BY id DESC", (pid,)).fetchall()
        plans = conn.execute("SELECT id, title, content FROM project_plans WHERE project_id=? ORDER BY id DESC", (pid,)).fetchall()
        conn.close()

        owner_opts = []
        for u in users:
            label = (f"{u['first_name']} {u['last_name']}".strip() or u["username"])
            sel = "selected" if u["id"] == project["created_by"] else ""
            owner_opts.append(f"<option value='{u['id']}' {sel}>{html.escape(label)} ({html.escape(u['username'])})</option>")

        av_opts = []
        for u in available:
            label = (f"{u['first_name']} {u['last_name']}".strip() or u["username"])
            av_opts.append(f"<option value='{u['id']}'>{html.escape(label)} ({html.escape(u['username'])})</option>")
        if not av_opts:
            av_opts = ["<option value='' disabled>Keine verfügbaren Benutzer</option>"]

        assigned_html = []
        for u in assigned:
            label = (f"{u['first_name']} {u['last_name']}".strip() or u["username"])
            assigned_html.append(
                "<li class='list-group-item d-flex justify-content-between align-items-center'>"
                f"<span>{html.escape(label)} <span class='text-muted'>({html.escape(u['username'])})</span></span>"
                "<form method='post' class='mb-0'><input type='hidden' name='action' value='remove_editor'>"
                f"<input type='hidden' name='editor_user_id' value='{u['id']}'><button class='btn btn-sm btn-outline-danger'>Entfernen</button></form></li>"
            )
        if not assigned_html:
            assigned_html = ["<li class='list-group-item text-muted'>Keine Bearbeiter zugeordnet.</li>"]

        address_html = []
        for a in addresses:
            address_html.append(
                "<div class='border rounded p-2 mb-2'><form method='post' class='row g-2'>"
                "<input type='hidden' name='action' value='edit_address'>"
                f"<input type='hidden' name='address_id' value='{a['id']}'>"
                f"<div class='col-md-4'><input class='form-control' name='title' value='{html.escape(a['title'])}'></div>"
                f"<div class='col-md-6'><input class='form-control' name='address' value='{html.escape(a['address'])}'></div>"
                "<div class='col-md-2 d-flex gap-2'><button class='btn btn-sm btn-primary'>Speichern</button></form>"
                "<form method='post'><input type='hidden' name='action' value='delete_address'>"
                f"<input type='hidden' name='address_id' value='{a['id']}'><button class='btn btn-sm btn-danger'>Löschen</button></form></div></div>"
            )
        if not address_html:
            address_html = ["<p class='text-muted'>Keine Adressen vorhanden.</p>"]

        plan_html = []
        for pl in plans:
            plan_html.append(
                "<div class='border rounded p-2 mb-2'><form method='post' class='row g-2'>"
                "<input type='hidden' name='action' value='edit_plan'>"
                f"<input type='hidden' name='plan_id' value='{pl['id']}'>"
                f"<div class='col-md-4'><input class='form-control' name='title' value='{html.escape(pl['title'])}'></div>"
                f"<div class='col-md-6'><textarea class='form-control' name='content' rows='2'>{html.escape(pl['content'])}</textarea></div>"
                "<div class='col-md-2 d-flex gap-2'><button class='btn btn-sm btn-primary'>Speichern</button></form>"
                "<form method='post'><input type='hidden' name='action' value='delete_plan'>"
                f"<input type='hidden' name='plan_id' value='{pl['id']}'><button class='btn btn-sm btn-danger'>Löschen</button></form></div></div>"
            )
        if not plan_html:
            plan_html = ["<p class='text-muted'>Keine Pläne vorhanden.</p>"]

        body = (
            "<h2>Projektdetails</h2><form method='post' class='row g-3'>"
            "<input type='hidden' name='action' value='save'>"
            f"<div class='col-md-4'><label class='form-label'>Projektnummer</label><input class='form-control' name='project_number' value='{html.escape(project['project_number'])}' required></div>"
            f"<div class='col-md-4'><label class='form-label'>Projektname</label><input class='form-control' name='project_name' value='{html.escape(project['project_name'])}' required></div>"
            f"<div class='col-md-4'><label class='form-label'>Projektadresse</label><input class='form-control' name='project_address' value='{html.escape(project['project_address'])}' required></div>"
            f"<div class='col-md-6'><label class='form-label'>Projektbesitzer</label><select class='form-select' name='owner_user_id'>{''.join(owner_opts)}</select></div>"
            f"<div class='col-md-6'><label class='form-label'>Erstellt</label><input class='form-control' value='{html.escape(project['created_at'])}' disabled></div>"
            "<div class='col-12 d-flex gap-2'><button class='btn btn-primary'>Speichern</button></form>"
            "<form method='post'><input type='hidden' name='action' value='delete'><button class='btn btn-danger'>Löschen</button></form>"
            "<a class='btn btn-outline-secondary' href='/projects'>Zurück</a></div>"
            "<hr><h3 class='h5'>Bearbeiter zuordnen</h3><form method='post' class='row g-2 align-items-end mb-2'>"
            "<input type='hidden' name='action' value='add_editor'>"
            f"<div class='col-md-8'><select class='form-select' name='editor_user_id'>{''.join(av_opts)}</select></div>"
            f"<div class='col-md-4'><button class='btn btn-success w-100' {'disabled' if 'Keine verfügbaren Benutzer' in av_opts[0] else ''}>Zuordnen</button></div>"
            "</form><ul class='list-group mb-4'>"
            f"{''.join(assigned_html)}</ul>"
            "<h3 class='h5'>Adressen verwalten</h3>"
            "<form method='post' class='row g-2 mb-2'><input type='hidden' name='action' value='add_address'>"
            "<div class='col-md-4'><input class='form-control' name='title' placeholder='Bezeichnung' required></div>"
            "<div class='col-md-6'><input class='form-control' name='address' placeholder='Adresse' required></div>"
            "<div class='col-md-2'><button class='btn btn-success w-100'>Anlegen</button></div></form>"
            f"{''.join(address_html)}"
            "<hr><h3 class='h5'>Pläne verwalten (Text)</h3>"
            "<form method='post' class='row g-2 mb-2'><input type='hidden' name='action' value='add_plan'>"
            "<div class='col-md-4'><input class='form-control' name='title' placeholder='Titel' required></div>"
            "<div class='col-md-6'><textarea class='form-control' name='content' rows='2' placeholder='Planinhalt' required></textarea></div>"
            "<div class='col-md-2'><button class='btn btn-success w-100'>Anlegen</button></div></form>"
            f"{''.join(plan_html)}"
        )
        page = layout("Projektdetails", body, user, flash)
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
            return forbid(start_response, user, "Nur der Admin kann Benutzer anlegen, bearbeiten und löschen.")

        query = parse_qs(environ.get("QUERY_STRING", ""))
        sort = query.get("sort", ["role"])[0]
        direction = query.get("dir", ["asc"])[0].lower()
        if sort not in {"first_name", "last_name", "username", "email", "role"}:
            sort = "role"
        if direction not in {"asc", "desc"}:
            direction = "asc"

        conn = db_connect()
        flash = None
        if method == "POST":
            form = parse_form(environ)
            if form.get("action") == "delete":
                uid = form.get("user_id", "")
                if uid.isdigit() and str(user["id"]) != uid:
                    conn.execute("DELETE FROM users WHERE id=?", (uid,))
                    conn.commit()
                    flash = {"kind": "success", "msg": "Benutzer gelöscht."}

        users = conn.execute(
            f"SELECT id, first_name, last_name, username, email, role FROM users ORDER BY {sort} {direction.upper()}, id ASC"
        ).fetchall()
        conn.close()

        rows = []
        for u in users:
            rows.append(
                "<tr>"
                f"<td>{html.escape(u['first_name'])}</td><td>{html.escape(u['last_name'])}</td><td>{html.escape(u['username'])}</td><td>{html.escape(u['email'])}</td><td>{role_badge(u['role'])}</td>"
                "<td><div class='d-flex gap-2'>"
                f"<a class='btn btn-sm btn-outline-secondary' href='/admin/users/{u['id']}'>Bearbeiten</a>"
                "<form method='post'><input type='hidden' name='action' value='delete'>"
                f"<input type='hidden' name='user_id' value='{u['id']}'><button class='btn btn-sm btn-outline-danger'>Löschen</button></form></div></td></tr>"
            )

        headers = []
        for col, label in (("first_name", "Vorname"), ("last_name", "Nachname"), ("username", "Benutzername"), ("email", "E-Mailadresse"), ("role", "Rolle")):
            nxt = "desc" if (sort == col and direction == "asc") else "asc"
            arrow = " ▲" if sort == col and direction == "asc" else (" ▼" if sort == col else "")
            headers.append(f"<th><a class='link-dark text-decoration-none' href='/admin/users?sort={col}&dir={nxt}'>{label}{arrow}</a></th>")

        body = (
            "<div class='d-flex justify-content-between align-items-center mb-3'><h2 class='mb-0'>Benutzerverwaltung</h2>"
            "<a class='btn btn-success' href='/admin/users/new'>Neuen Benutzer anlegen</a></div>"
            "<div class='table-responsive'><table class='table table-striped align-middle'>"
            f"<thead><tr>{''.join(headers)}<th>Aktionen</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        )
        page = layout("Benutzerverwaltung", body, user, flash)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path == "/admin/users/new":
        if user["role"] != "admin":
            return forbid(start_response, user, "Nur der Admin kann Benutzer anlegen, bearbeiten und löschen.")
        conn = db_connect()
        if method == "POST":
            f = parse_form(environ)
            first_name = f.get("first_name", "").strip()
            last_name = f.get("last_name", "").strip()
            username = f.get("username", "").strip()
            email = f.get("email", "").strip()
            password = f.get("password", "")
            role = f.get("role", "bearbeiter")
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
        opts = "".join([f"<option value='{r}'>{ROLE_LABELS[r]}</option>" for r in ROLES])
        body = (
            "<h2>Neuen Benutzer anlegen</h2><form method='post' class='row g-3'>"
            "<div class='col-md-6'><label class='form-label'>Vorname</label><input class='form-control' name='first_name'></div>"
            "<div class='col-md-6'><label class='form-label'>Nachname</label><input class='form-control' name='last_name'></div>"
            "<div class='col-md-6'><label class='form-label'>Benutzername</label><input class='form-control' name='username' required></div>"
            "<div class='col-md-6'><label class='form-label'>E-Mailadresse</label><input class='form-control' name='email' type='email' required></div>"
            "<div class='col-md-6'><label class='form-label'>Passwort</label><input class='form-control' type='password' name='password' required minlength='6'></div>"
            f"<div class='col-md-6'><label class='form-label'>Rolle</label><select class='form-select' name='role'>{opts}</select></div>"
            "<div class='col-12 d-flex gap-2'><button class='btn btn-success'>Speichern</button><a class='btn btn-outline-secondary' href='/admin/users'>Zurück</a></div></form>"
        )
        page = layout("Benutzer anlegen", body, user, flash)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [page.encode()]

    if path.startswith("/admin/users/"):
        if user["role"] != "admin":
            return forbid(start_response, user, "Nur der Admin kann Benutzer anlegen, bearbeiten und löschen.")
        uid = path.split("/")[-1]
        if not uid.isdigit():
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Not found"]
        conn = db_connect()
        target = conn.execute("SELECT id, first_name, last_name, username, email, role, created_at FROM users WHERE id=?", (uid,)).fetchone()
        if not target:
            conn.close(); start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")]); return [b"Not found"]
        flash = None
        if method == "POST":
            f = parse_form(environ)
            action = f.get("action", "save")
            if action == "delete":
                if str(user["id"]) == uid:
                    flash = {"kind": "warning", "msg": "Du kannst dich nicht selbst löschen."}
                else:
                    conn.execute("DELETE FROM users WHERE id=?", (uid,))
                    conn.commit(); conn.close(); return redirect(start_response, "/admin/users")
            else:
                first_name = f.get("first_name", "").strip(); last_name = f.get("last_name", "").strip()
                username = f.get("username", "").strip(); email = f.get("email", "").strip(); role = f.get("role", target["role"])
                password = f.get("password", "")
                if role not in ROLES: role = target["role"]
                exists_user = conn.execute("SELECT id FROM users WHERE username=? AND id != ?", (username, uid)).fetchone()
                exists_email = conn.execute("SELECT id FROM users WHERE email=? AND id != ?", (email, uid)).fetchone()
                if len(username) < 3 or "@" not in email:
                    flash = {"kind": "warning", "msg": "Benutzername >=3 und gültige E-Mailadresse erforderlich."}
                elif exists_user:
                    flash = {"kind": "danger", "msg": "Benutzername bereits vergeben."}
                elif exists_email:
                    flash = {"kind": "danger", "msg": "E-Mailadresse bereits vergeben."}
                elif password and len(password) < 6:
                    flash = {"kind": "warning", "msg": "Neues Passwort muss mindestens 6 Zeichen haben."}
                else:
                    if password:
                        conn.execute("UPDATE users SET first_name=?, last_name=?, username=?, email=?, role=?, password=? WHERE id=?", (first_name,last_name,username,email,role,hash_password(password),uid))
                    else:
                        conn.execute("UPDATE users SET first_name=?, last_name=?, username=?, email=?, role=? WHERE id=?", (first_name,last_name,username,email,role,uid))
                    conn.commit(); flash = {"kind": "success", "msg": "Benutzer gespeichert."}
            target = conn.execute("SELECT id, first_name, last_name, username, email, role, created_at FROM users WHERE id=?", (uid,)).fetchone()
        conn.close()
        opts = "".join([f"<option value='{r}' {'selected' if r==target['role'] else ''}>{ROLE_LABELS[r]}</option>" for r in ROLES])
        body = (
            "<h2>Benutzerdetails</h2><form method='post' class='row g-3'><input type='hidden' name='action' value='save'>"
            f"<div class='col-md-6'><label class='form-label'>Vorname</label><input class='form-control' name='first_name' value='{html.escape(target['first_name'])}'></div>"
            f"<div class='col-md-6'><label class='form-label'>Nachname</label><input class='form-control' name='last_name' value='{html.escape(target['last_name'])}'></div>"
            f"<div class='col-md-6'><label class='form-label'>Benutzername</label><input class='form-control' name='username' value='{html.escape(target['username'])}' required></div>"
            f"<div class='col-md-6'><label class='form-label'>E-Mailadresse</label><input class='form-control' type='email' name='email' value='{html.escape(target['email'])}' required></div>"
            f"<div class='col-md-6'><label class='form-label'>Rolle</label><select class='form-select' name='role'>{opts}</select></div>"
            "<div class='col-md-6'><label class='form-label'>Neues Passwort (optional)</label><input class='form-control' type='password' name='password'></div>"
            f"<div class='col-md-6'><label class='form-label'>Erstellt</label><input class='form-control' value='{html.escape(target['created_at'])}' disabled></div>"
            "<div class='col-12 d-flex gap-2'><button class='btn btn-primary'>Speichern</button></form>"
            "<form method='post'><input type='hidden' name='action' value='delete'><button class='btn btn-danger'>Löschen</button></form>"
            "<a class='btn btn-outline-secondary' href='/admin/users'>Zurück</a></div>"
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
