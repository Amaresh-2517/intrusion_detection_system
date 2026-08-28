"""
Entry point for the Flask dashboard. Run this in a separate terminal
from run_sniffer.py — they're independent processes sharing the SQLite DB.

Usage:
    python run_dashboard.py
"""

from flask import Flask
from app.database.db import init_db
from app.dashboard.routes import bp as dashboard_bp
from app.config import DASHBOARD_HOST, DASHBOARD_PORT, FLASK_SECRET_KEY


def create_app():
    # static_folder=None: the dashboard blueprint owns /static (see routes.py),
    # since there's no separate app-level static folder in this project.
    app = Flask(__name__, static_folder=None)
    app.secret_key = FLASK_SECRET_KEY  # required for session-based login
    app.register_blueprint(dashboard_bp)
    return app


if __name__ == "__main__":
    init_db()
    app = create_app()
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=True)
