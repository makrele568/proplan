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
            path_only, query = path.split("?", 1)
            environ["PATH_INFO"] = path_only
            environ["QUERY_STRING"] = query
        else:
            environ["PATH_INFO"] = path
            environ["QUERY_STRING"] = ""
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

    def test_admin_can_login_with_username_not_email(self):
        cookie = self.login_and_get_cookie("admin", "admin123")
        status, _, body = self.request("/dashboard", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Dashboard", body)

    def test_password_hashed_in_db(self):
        conn = sqlite3.connect(proplan.DB_PATH)
        pw = conn.execute("SELECT password FROM users WHERE username='admin'").fetchone()[0]
        conn.close()
        self.assertTrue(pw.startswith("pbkdf2_sha256$"))
        self.assertNotEqual(pw, "admin123")

    def test_register_disabled(self):
        status, _, _ = self.request("/register")
        self.assertTrue(status.startswith("404"))

    def test_non_admin_forbidden_in_user_management(self):
        conn = sqlite3.connect(proplan.DB_PATH)
        conn.execute(
            "INSERT INTO users (username, email, first_name, last_name, password, role) VALUES (?, ?, ?, ?, ?, ?)",
            ("bearb", "bearb@example.com", "Bea", "Arbeiter", proplan.hash_password("secret12"), "bearbeiter"),
        )
        conn.commit()
        conn.close()

        cookie = self.login_and_get_cookie("bearb", "secret12")
        status, _, body = self.request("/admin/users", cookie=cookie)
        self.assertTrue(status.startswith("403"))
        self.assertIn("Nur der Admin", body)

    def test_user_list_columns_and_sorting(self):
        cookie = self.login_and_get_cookie("admin", "admin123")
        status, _, body = self.request("/admin/users?sort=username&dir=asc", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Vorname", body)
        self.assertIn("Nachname", body)
        self.assertIn("Benutzername", body)
        self.assertIn("E-Mailadresse", body)
        self.assertIn("sort=first_name", body)
        self.assertIn("sort=last_name", body)
        self.assertIn("sort=username", body)
        self.assertIn("sort=email", body)
        self.assertIn("sort=role", body)

    def test_admin_create_edit_delete_user(self):
        cookie = self.login_and_get_cookie("admin", "admin123")

        status, headers, _ = self.request(
            "/admin/users/new",
            "POST",
            {
                "first_name": "Max",
                "last_name": "Mustermann",
                "username": "maxm",
                "email": "maxm@example.com",
                "password": "secret12",
                "role": "bearbeiter",
            },
            cookie=cookie,
        )
        self.assertTrue(status.startswith("302"))
        self.assertEqual(headers.get("Location"), "/admin/users")

        conn = sqlite3.connect(proplan.DB_PATH)
        uid = conn.execute("SELECT id FROM users WHERE username='maxm'").fetchone()[0]
        pw = conn.execute("SELECT password FROM users WHERE id=?", (uid,)).fetchone()[0]
        conn.close()
        self.assertTrue(pw.startswith("pbkdf2_sha256$"))

        status, _, body = self.request(
            f"/admin/users/{uid}",
            "POST",
            {
                "action": "save",
                "first_name": "Maximilian",
                "last_name": "Mustermann",
                "username": "maxm",
                "email": "maximilian@example.com",
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


if __name__ == "__main__":
    unittest.main()
