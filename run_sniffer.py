"""
Entry point for the capture + detection process.
Run with elevated privileges (sudo on Linux/macOS, Administrator on Windows)
since raw packet capture requires it.

Usage:
    sudo python run_sniffer.py
"""

from app.database.db import init_db
from app.capture.sniffer import start_sniffer

if __name__ == "__main__":
    init_db()
    start_sniffer()
