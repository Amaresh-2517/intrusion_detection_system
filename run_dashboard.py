"""
Entry point for the Flask dashboard. Run this in a separate terminal
from run_sniffer.py — they're independent processes sharing the SQLite DB.

Usage:
    python3 run_dashboard.py
"""

from flask import Flask
from app.database.db import init_db
from app.dashboard.routes import bp as dashboard_bp
from app.config import (
    DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_DEBUG, FLASK_SECRET_KEY,
    SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE, SESSION_COOKIE_SECURE,
    validate_dashboard_config,
)


def create_app():
    validate_dashboard_config()
    # static_folder=None: the dashboard blueprint owns /static (see routes.py),
    # since there's no separate app-level static folder in this project.
    app = Flask(__name__, static_folder=None)
    app.secret_key = FLASK_SECRET_KEY  # required for session-based login
    app.config.update(
        SESSION_COOKIE_HTTPONLY=SESSION_COOKIE_HTTPONLY,
        SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
        SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    )
    app.register_blueprint(dashboard_bp)
    return app


if __name__ == "__main__":
    init_db()
    app = create_app()
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=DASHBOARD_DEBUG)
