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
        environ["PATH_INFO"] = path
        environ["REQUEST_METHOD"] = method

        raw = urlencode(data or {}).encode("utf-8")
        environ["CONTENT_LENGTH"] = str(len(raw))
        environ["wsgi.input"] = BytesIO(raw)
        if cookie:
            environ["HTTP_COOKIE"] = cookie

        status_holder = {}
        headers_holder = {}

        def start_response(status, headers):
            status_holder["status"] = status
            headers_holder["headers"] = headers

        resp_body = b"".join(proplan.app(environ, start_response)).decode("utf-8")
        return status_holder["status"], dict(headers_holder["headers"]), resp_body

    def login_and_get_cookie(self, username, password):
        status, headers, _ = self.request("/login", "POST", {"username": username, "password": password})
        self.assertTrue(status.startswith("302"))
        return headers.get("Set-Cookie", "").split(";", 1)[0]

    def test_login_page_is_standalone(self):
        status, _, body = self.request("/login")
        self.assertTrue(status.startswith("200"))
        self.assertIn("<title>Login</title>", body)
        self.assertNotIn("Navigation", body)
        self.assertNotIn("ProPlan</a>", body)

    def test_register_disabled(self):
        status, _, _ = self.request("/register")
        self.assertTrue(status.startswith("404"))

    def test_non_admin_forbidden_in_user_management(self):
        conn = sqlite3.connect(proplan.DB_PATH)
        conn.execute(
            "INSERT INTO users (username, first_name, last_name, password, role) VALUES (?, ?, ?, ?, ?)",
            ("bearb@example.com", "Bea", "Arbeiter", "secret12", "bearbeiter"),
        )
        conn.commit()
        conn.close()

        cookie = self.login_and_get_cookie("bearb@example.com", "secret12")
        status, _, body = self.request("/admin/users", cookie=cookie)
        self.assertTrue(status.startswith("403"))
        self.assertIn("Nur der Admin", body)

    def test_user_list_columns_and_actions(self):
        cookie = self.login_and_get_cookie("admin@example.com", "admin123")
        status, _, body = self.request("/admin/users", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Vorname", body)
        self.assertIn("Nachname", body)
        self.assertIn("E-Mailadresse", body)
        self.assertIn("Rolle", body)
        self.assertIn("sort=first_name", body)
        self.assertIn("sort=last_name", body)
        self.assertIn("sort=username", body)
        self.assertIn("sort=role", body)
        self.assertIn("Bearbeiten", body)
        self.assertIn("Löschen", body)
        self.assertIn("Projektverwaltung", body)

    def test_admin_create_edit_delete_user(self):
        cookie = self.login_and_get_cookie("admin@example.com", "admin123")

        status, headers, _ = self.request(
            "/admin/users/new",
            "POST",
            {
                "first_name": "Max",
                "last_name": "Mustermann",
                "username": "maxm@example.com",
                "password": "secret12",
                "role": "bearbeiter",
            },
            cookie=cookie,
        )
        self.assertTrue(status.startswith("302"))
        self.assertEqual(headers.get("Location"), "/admin/users")

        conn = sqlite3.connect(proplan.DB_PATH)
        uid = conn.execute("SELECT id FROM users WHERE username='maxm@example.com'").fetchone()[0]
        conn.close()

        status, _, body = self.request(f"/admin/users/{uid}", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Benutzerdetails", body)

        status, _, body = self.request(
            f"/admin/users/{uid}",
            "POST",
            {
                "action": "save",
                "first_name": "Maximilian",
                "last_name": "Mustermann",
                "username": "maxm@example.com",
                "role": "projektleiter",
                "password": "",
            },
            cookie=cookie,
        )
        self.assertTrue(status.startswith("200"))
        self.assertIn("Benutzer gespeichert", body)

        status, headers, _ = self.request(
            f"/admin/users/{uid}",
            "POST",
            {"action": "delete"},
            cookie=cookie,
        )
        self.assertTrue(status.startswith("302"))
        self.assertEqual(headers.get("Location"), "/admin/users")

    def test_navigation_admin_link_hidden_for_non_admin(self):
        conn = sqlite3.connect(proplan.DB_PATH)
        conn.execute(
            "INSERT INTO users (username, first_name, last_name, password, role) VALUES (?, ?, ?, ?, ?)",
            ("pl@example.com", "Pia", "Leiter", "secret12", "projektleiter"),
        )
        conn.commit()
        conn.close()

        cookie = self.login_and_get_cookie("pl@example.com", "secret12")
        status, _, body = self.request("/dashboard", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Projektverwaltung", body)
        self.assertNotIn("Benutzerverwaltung</a>", body)

        status, _, body = self.request("/projects", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Projektverwaltung", body)



if __name__ == "__main__":
    unittest.main()
