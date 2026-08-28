"""
Minimal session-based authentication.

Deliberately not using Flask-Login or any auth library — for an
academic project, a plain session flag is easier to explain in a
viva than pulling in another dependency, and it's sufficient for a
single-operator SOC console. Swap for something more robust
(hashed passwords, multiple users, rate-limited login) before ever
deploying this beyond a local demo.
"""

from functools import wraps
from flask import session, redirect, url_for, request

from app.config import DASHBOARD_USERNAME, DASHBOARD_PASSWORD


def check_credentials(username, password):
    return username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("dashboard.login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped
