"""
IDS Alerter — formats and prints color-coded alerts to the terminal.
Also delegates to the logger module to persist events.
"""

from ids.logger import log_event

# ANSI color codes
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"

_COLORS = {
    "PORT_SCAN":     _YELLOW,
    "PING_FLOOD":    _RED,
    "BRUTE_FORCE":   _RED,
    "TRAFFIC_SPIKE": _CYAN,
}

_ICONS = {
    "PORT_SCAN":     "🔍",
    "PING_FLOOD":    "🌊",
    "BRUTE_FORCE":   "🔑",
    "TRAFFIC_SPIKE": "📈",
}


def handle_alert(event: dict):
    """Called by AttackDetector when an attack is detected."""
    attack = event.get("attack", "UNKNOWN")
    color  = _COLORS.get(attack, _GREEN)
    icon   = _ICONS.get(attack, "⚠️")

    print(
        f"\n{_BOLD}{color}"
        f"{'─'*60}\n"
        f"  {icon}  ALERT: {attack}\n"
        f"  Time   : {event['timestamp']}\n"
        f"  Source : {event['src_ip']}\n"
        f"  Detail : {event['detail']}\n"
        f"{'─'*60}"
        f"{_RESET}\n"
    )

    # Persist to log file
    log_event(event)
