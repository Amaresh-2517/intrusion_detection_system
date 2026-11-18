"""
Minimal session-based authentication.

Deliberately not using Flask-Login or any auth library — for an
academic project, a plain session flag is easier to explain in a
viva than pulling in another dependency, and it's sufficient for a
single-operator SOC console. Swap for something more robust
(hashed passwords, multiple users, rate-limited login) before ever
deploying this beyond a local demo.
"""

import secrets
import threading
import time
from functools import wraps
from urllib.parse import urlparse

from flask import session, redirect, url_for, request
from werkzeug.security import check_password_hash

from app.config import (
    DASHBOARD_USERNAME, DASHBOARD_PASSWORD_HASH,
    LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS,
)

_login_failures = {}
_login_lock = threading.Lock()


def check_credentials(username, password):
    if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD_HASH:
        return False
    try:
        return username == DASHBOARD_USERNAME and check_password_hash(
            DASHBOARD_PASSWORD_HASH, password
        )
    except ValueError:
        return False


def is_safe_redirect(target):
    """Only allow an on-site absolute path as the post-login destination.

    Browsers treat backslashes as path separators in redirect URLs. Reject
    them explicitly so a value such as ``/\\attacker.example`` cannot be
    interpreted as an external URL after the Location header is followed.
    """
    if not target or not target.startswith("/") or target.startswith("//"):
        return False
    if "\\" in target or any(ord(char) < 32 or ord(char) == 127 for char in target):
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc


def csrf_token():
    """Return the per-session token used by state-changing dashboard forms."""
    return session.setdefault("csrf_token", secrets.token_urlsafe(32))


def valid_csrf_token(token):
    expected = session.get("csrf_token", "")
    return bool(token and expected) and secrets.compare_digest(token, expected)


def login_is_rate_limited(remote_addr):
    now = time.monotonic()
    with _login_lock:
        attempts = [t for t in _login_failures.get(remote_addr, []) if now - t < LOGIN_WINDOW_SECONDS]
        _login_failures[remote_addr] = attempts
        return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failed_login(remote_addr):
    with _login_lock:
        _login_failures.setdefault(remote_addr, []).append(time.monotonic())


def clear_failed_logins(remote_addr):
    with _login_lock:
        _login_failures.pop(remote_addr, None)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("dashboard.login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped
