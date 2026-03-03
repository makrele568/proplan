import os
import sqlite3
import tempfile
import unittest
from io import BytesIO
from urllib.parse import urlencode
from wsgiref.util import setup_testing_defaults

import app as proplan


class AppTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        proplan.DB_PATH = os.path.join(self.tmpdir.name, "test.sqlite")
        proplan.SESSIONS.clear()
        proplan.init_db()

    def tearDown(self):
        self.tmpdir.cleanup()

    def request(self, path, method="GET", data=None, cookie=""):
        environ = {}
        setup_testing_defaults(environ)
        if "?" in path:
            p, q = path.split("?", 1)
            environ["PATH_INFO"] = p
            environ["QUERY_STRING"] = q
        else:
            environ["PATH_INFO"] = path
            environ["QUERY_STRING"] = ""
        environ["REQUEST_METHOD"] = method
        raw = urlencode(data or {}).encode("utf-8")
        environ["CONTENT_LENGTH"] = str(len(raw))
        environ["wsgi.input"] = BytesIO(raw)
        if cookie:
            environ["HTTP_COOKIE"] = cookie

        st, hd = {}, {}

        def start_response(status, headers):
            st["status"] = status
            hd["headers"] = headers

        body = b"".join(proplan.app(environ, start_response)).decode("utf-8")
        return st["status"], dict(hd["headers"]), body

    def login(self, username, password):
        status, headers, _ = self.request("/login", "POST", {"username": username, "password": password})
        self.assertTrue(status.startswith("302"))
        return headers.get("Set-Cookie", "").split(";", 1)[0]

    def test_admin_login_and_hash(self):
        cookie = self.login("admin", "admin123")
        status, _, _ = self.request("/dashboard", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        conn = sqlite3.connect(proplan.DB_PATH)
        pw = conn.execute("SELECT password FROM users WHERE username='admin'").fetchone()[0]
        conn.close()
        self.assertTrue(pw.startswith("pbkdf2_sha256$"))

    def test_dashboard_lists_authorized_projects(self):
        conn = sqlite3.connect(proplan.DB_PATH)
        conn.execute(
            "INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
            ("u1", "u1@example.com", proplan.hash_password("secret12"), "bearbeiter"),
        )
        conn.execute(
            "INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
            ("u2", "u2@example.com", proplan.hash_password("secret12"), "bearbeiter"),
        )
        conn.execute(
            "INSERT INTO projects (project_number,project_name,project_address,created_by) VALUES ('P1','One','Addr 1',2)"
        )
        conn.execute(
            "INSERT INTO projects (project_number,project_name,project_address,created_by) VALUES ('P2','Two','Addr 2',3)"
        )
        conn.execute("INSERT INTO project_editors (project_id,user_id) VALUES (2,2)")
        conn.commit()
        conn.close()

        cookie = self.login("u1", "secret12")
        status, _, body = self.request("/dashboard", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("P1", body)
        self.assertIn("P2", body)

    def test_project_layout_and_new_button(self):
        cookie = self.login("admin", "admin123")
        status, _, body = self.request("/projects", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Neues Projekt anlegen", body)
        self.assertIn("table", body)

    def test_any_user_can_create_project_owner_only_edit(self):
        conn = sqlite3.connect(proplan.DB_PATH)
        conn.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)", ("a", "a@example.com", proplan.hash_password("secret12"), "bearbeiter"))
        conn.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)", ("b", "b@example.com", proplan.hash_password("secret12"), "bearbeiter"))
        conn.commit(); conn.close()

        a_cookie = self.login("a", "secret12")
        status, headers, _ = self.request("/projects/new", "POST", {"project_number": "PX", "project_name": "Proj", "project_address": "Street 1"}, cookie=a_cookie)
        self.assertTrue(status.startswith("302"))
        self.assertEqual(headers.get("Location"), "/projects")

        conn = sqlite3.connect(proplan.DB_PATH)
        pid = conn.execute("SELECT id FROM projects WHERE project_number='PX'").fetchone()[0]
        conn.close()

        # owner can edit and change owner
        status, _, body = self.request(f"/projects/{pid}", "POST", {
            "action": "save", "project_number": "PX", "project_name": "Proj2", "project_address": "Street 2", "owner_user_id": "3"
        }, cookie=a_cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Projekt gespeichert", body)

        # old owner cannot edit anymore
        status, _, body = self.request(f"/projects/{pid}", cookie=a_cookie)
        self.assertTrue(status.startswith("403"))

        # new owner can edit
        b_cookie = self.login("b", "secret12")
        status, _, body = self.request(f"/projects/{pid}", cookie=b_cookie)
        self.assertTrue(status.startswith("200"))

    def test_project_editors_addresses_plans_crud(self):
        cookie = self.login("admin", "admin123")
        self.request("/admin/users/new", "POST", {
            "username": "editor", "email": "ed@example.com", "password": "secret12", "role": "bearbeiter"
        }, cookie=cookie)
        self.request("/projects/new", "POST", {
            "project_number": "P-9", "project_name": "Nine", "project_address": "Road 9"
        }, cookie=cookie)

        conn = sqlite3.connect(proplan.DB_PATH)
        pid = conn.execute("SELECT id FROM projects WHERE project_number='P-9'").fetchone()[0]
        ed_id = conn.execute("SELECT id FROM users WHERE username='editor'").fetchone()[0]
        conn.close()

        status, _, body = self.request(f"/projects/{pid}", "POST", {"action": "add_editor", "editor_user_id": str(ed_id)}, cookie=cookie)
        self.assertIn("Bearbeiter zugeordnet", body)

        status, _, body = self.request(f"/projects/{pid}", "POST", {"action": "add_address", "title": "Büro", "address": "Main 1"}, cookie=cookie)
        self.assertIn("Adresse angelegt", body)

        conn = sqlite3.connect(proplan.DB_PATH)
        aid = conn.execute("SELECT id FROM project_addresses WHERE project_id=?", (pid,)).fetchone()[0]
        conn.close()

        status, _, body = self.request(f"/projects/{pid}", "POST", {"action": "edit_address", "address_id": str(aid), "title": "Büro2", "address": "Main 2"}, cookie=cookie)
        self.assertIn("Adresse gespeichert", body)

        status, _, body = self.request(f"/projects/{pid}", "POST", {"action": "add_plan", "title": "Plan A", "content": "Text"}, cookie=cookie)
        self.assertIn("Plan angelegt", body)

        conn = sqlite3.connect(proplan.DB_PATH)
        plid = conn.execute("SELECT id FROM project_plans WHERE project_id=?", (pid,)).fetchone()[0]
        conn.close()

        status, _, body = self.request(f"/projects/{pid}", "POST", {"action": "edit_plan", "plan_id": str(plid), "title": "Plan B", "content": "Text2"}, cookie=cookie)
        self.assertIn("Plan gespeichert", body)

        status, _, body = self.request(f"/projects/{pid}", "POST", {"action": "delete_plan", "plan_id": str(plid)}, cookie=cookie)
        self.assertIn("Plan gelöscht", body)

        status, _, body = self.request(f"/projects/{pid}", "POST", {"action": "delete_address", "address_id": str(aid)}, cookie=cookie)
        self.assertIn("Adresse gelöscht", body)

    def test_internal_ids_hidden_in_ui(self):
        cookie = self.login("admin", "admin123")
        status, _, body = self.request("/admin/users", cookie=cookie)
        self.assertNotIn("Interne Benutzer-ID", body)
        status, _, body = self.request("/projects", cookie=cookie)
        self.assertNotIn("Interne Projekt-ID", body)


if __name__ == "__main__":
    unittest.main()
