"""Security regression tests for dashboard authentication routes."""

import unittest
from unittest.mock import patch

from run_dashboard import create_app


class DashboardSecurityTests(unittest.TestCase):

    def setUp(self):
        with patch("run_dashboard.validate_dashboard_config"):
            self.app = create_app()
        self.app.config.update(TESTING=True, SECRET_KEY="test-session-secret")
        self.client = self.app.test_client()

    def _csrf_token(self):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_login_rejects_external_next_url(self):
        with patch("app.dashboard.routes.check_credentials", return_value=True):
            response = self.client.post(
                "/login?next=https://example.invalid/after-login",
                data={"username": "any", "password": "any", "csrf_token": self._csrf_token()},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

    def test_login_allows_local_next_url(self):
        with patch("app.dashboard.routes.check_credentials", return_value=True):
            response = self.client.post(
                "/login?next=/alerts",
                data={"username": "any", "password": "any", "csrf_token": self._csrf_token()},
                follow_redirects=False,
            )
        self.assertEqual(response.headers["Location"], "/alerts")

    def test_logout_requires_post_and_csrf_token(self):
        with self.client.session_transaction() as session:
            session["logged_in"] = True
            session["csrf_token"] = "known-token"

        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.client.post("/logout").status_code, 400)
        response = self.client.post("/logout", data={"csrf_token": "known-token"})
        self.assertEqual(response.status_code, 302)
