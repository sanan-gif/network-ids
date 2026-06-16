"""
IDS Logger — appends alert events to a JSON-lines log file.
"""

import json
import os
from datetime import datetime
from threading import Lock

LOG_DIR  = os.path.join(os.path.dirname(__file__), "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "ids_alerts.json")

_lock = Lock()


def _ensure_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def log_event(event: dict):
    """Append a single alert event (dict) to the JSON log file."""
    _ensure_dir()
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")


def read_events(limit: int = 200) -> list:
    """Return the most recent `limit` events from the log file."""
    _ensure_dir()
    if not os.path.exists(LOG_FILE):
        return []
    with _lock:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    events = []
    for line in lines:
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events[-limit:]


def clear_log():
    """Wipe the log file (for testing / manual reset)."""
    _ensure_dir()
    with _lock:
        open(LOG_FILE, "w").close()
