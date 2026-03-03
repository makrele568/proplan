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

    def test_bootstrap_layout_visible(self):
        status, _, body = self.request("/login")
        self.assertTrue(status.startswith("200"))
        self.assertIn("bootstrap", body.lower())

    def test_register_with_role_and_login(self):
        status, _, _ = self.request(
            "/register",
            "POST",
            {
                "username": "alice",
                "first_name": "Alice",
                "last_name": "Muster",
                "password": "secret12",
                "role": "bearbeiter",
            },
        )
        self.assertTrue(status.startswith("302"))

        cookie = self.login_and_get_cookie("alice", "secret12")
        status, _, body = self.request("/dashboard", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("bearbeiter", body)

    def test_bearbeiter_forbidden_admin_area(self):
        self.request(
            "/register",
            "POST",
            {"username": "bob", "first_name": "Bob", "last_name": "Tester", "password": "secret12", "role": "bearbeiter"},
        )
        cookie = self.login_and_get_cookie("bob", "secret12")

        status, _, body = self.request("/admin/users", cookie=cookie)
        self.assertTrue(status.startswith("403"))
        self.assertIn("Nur der Admin", body)

    def test_projektleiter_can_access_but_not_escalate_admin(self):
        self.request(
            "/register",
            "POST",
            {
                "username": "planer",
                "first_name": "Petra",
                "last_name": "Leitung",
                "password": "secret12",
                "role": "projektleiter",
            },
        )
        conn = sqlite3.connect(proplan.DB_PATH)
        conn.execute(
            "INSERT INTO users (username, first_name, last_name, password, role) VALUES (?, ?, ?, ?, ?)",
            ("worker", "Willi", "Arbeiter", "x12345", "bearbeiter"),
        )
        conn.commit()
        conn.close()

        cookie = self.login_and_get_cookie("planer", "secret12")
        status, _, body = self.request("/admin/users", cookie=cookie)
        self.assertTrue(status.startswith("403"))
        self.assertIn("Nur der Admin", body)

        # projektleiter has no access anymore, admin-only management

    def test_root_redirects_to_login(self):
        status, headers, _ = self.request("/")
        self.assertTrue(status.startswith("302"))
        self.assertEqual(headers.get("Location"), "/login")

    def test_header_dropdown_and_create_user_option(self):
        cookie = self.login_and_get_cookie("admin", "admin123")
        status, _, body = self.request("/dashboard", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Mein Account", body)
        self.assertIn("Abmelden", body)

        status, _, body = self.request("/admin/users", cookie=cookie)
        self.assertTrue(status.startswith("200"))
        self.assertIn("Neuen Benutzer hinzufügen", body)
        self.assertIn("Bearbeiten", body)

        status, _, body = self.request(
            "/admin/users",
            "POST",
            {
                "action": "create_user",
                "username": "neuuser",
                "first_name": "Neue",
                "last_name": "Person",
                "password": "secret12",
                "role": "bearbeiter",
            },
            cookie=cookie,
        )
        self.assertTrue(status.startswith("200"))
        self.assertIn("wurde angelegt", body)

        status, _, body = self.request(
            "/admin/users",
            "POST",
            {
                "action": "edit_user",
                "user_id": "2",
                "first_name": "Neu",
                "last_name": "Benannt",
                "username": "neuuser",
                "role": "bearbeiter",
                "password": "",
            },
            cookie=cookie,
        )
        self.assertTrue(status.startswith("200"))
        self.assertIn("aktualisiert", body)


if __name__ == "__main__":
    unittest.main()
