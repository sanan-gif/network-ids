"""
Network Intrusion Detection System - Core Detector
Detects: Port Scan, Ping Flood, Brute Force, Traffic Spike
"""

import time
import json
import logging
from collections import defaultdict
from datetime import datetime
from threading import Lock

# ─────────────────────────── Thresholds ────────────────────────────
PORT_SCAN_THRESHOLD   = 20       # unique ports in window
PORT_SCAN_WINDOW      = 5        # seconds
PING_FLOOD_THRESHOLD  = 100      # ICMP packets / second
BRUTE_FORCE_THRESHOLD = 5        # failed attempts
BRUTE_FORCE_WINDOW    = 60       # seconds
TRAFFIC_SPIKE_RATIO   = 2.0      # multiplier above rolling average

# ───────────────────────────── Setup ───────────────────────────────
logging.basicConfig(level=logging.INFO, format=\"%(asctime)s [%(levelname)s] %(message)s\")
log = logging.getLogger(\"IDS\")


class AttackDetector:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback or self._default_alert

        # Port scan tracking: ip → {port: first_seen_timestamp}
        self._port_map   = defaultdict(dict)
        self._ps_lock    = Lock()

        # Ping flood tracking: ip → [timestamps]
        self._icmp_times = defaultdict(list)
        self._pf_lock    = Lock()

        # Brute force tracking: ip → [timestamps of failed attempts]
        self._bf_times   = defaultdict(list)
        self._bf_lock    = Lock()

        # Traffic spike tracking
        self._byte_samples = []
        self._rolling_avg  = 0.0
        self._ts_lock      = Lock()

        # Alert Cooldown Configuration
        self._cooldown_lock = Lock()
        self._cooldown_period = 10.0  # Time in seconds to suppress identical alerts
        self._last_alert_times = defaultdict(float)  # Tracks attack_type -> last_epoch_timestamp

    def check_port_scan(self, src_ip: str, dport: int):
        now = time.time()
        with self._ps_lock:
            # Clean up old ports outside the rolling window
            old_ports = [p for p, t in self._port_map[src_ip].items() if now - t > PORT_SCAN_WINDOW]
            for p in old_ports:
                del self._port_map[src_ip][p]

            # Log current unique port
            if dport not in self._port_map[src_ip]:
                self._port_map[src_ip][dport] = now

            if len(self._port_map[src_ip]) > PORT_SCAN_THRESHOLD:
                self._fire("PORT_SCAN", src_ip, 
                           f"Scanned {len(self._port_map[src_ip])} unique ports in {PORT_SCAN_WINDOW}s")
                self._port_map[src_ip].clear()  # reset

    def check_ping_flood(self, src_ip: str):
        now = time.time()
        with self._pf_lock:
            self._icmp_times[src_ip].append(now)
            # Keep only last 1 second of timestamps
            self._icmp_times[src_ip] = [t for t in self._icmp_times[src_ip] if now - t < 1.0]

            if len(self._icmp_times[src_ip]) > PING_FLOOD_THRESHOLD:
                self._fire("PING_FLOOD", src_ip, f"ICMP rate exceeded {len(self._icmp_times[src_ip])} pkts/s")
                self._icmp_times[src_ip] = []  # reset

    def check_brute_force(self, src_ip: str, service: str):
        now = time.time()
        with self._bf_lock:
            self._bf_times[src_ip].append(now)
            # Keep attempts within the history window
            self._bf_times[src_ip] = [t for t in self._bf_times[src_ip] if now - t < BRUTE_FORCE_WINDOW]

            times = self._bf_times[src_ip]
            if len(times) > BRUTE_FORCE_THRESHOLD:
                self._fire("BRUTE_FORCE", src_ip,
                           f"{len(times)} failed {service} attempts in {BRUTE_FORCE_WINDOW}s")
                self._bf_times[src_ip] = []   # reset

    def check_traffic_spike(self, bytes_per_second: float, top_talker_ip: str = "N/A"):
        """Evaluates traffic surges and attributes them to a source IP if possible."""
        now = time.time()
        with self._ts_lock:
            self._byte_samples.append((now, bytes_per_second))
            # Keep 60-second history
            self._byte_samples = [(t, b) for t, b in self._byte_samples if now - t < 60]

            if len(self._byte_samples) >= 5:
                avg = sum(b for _, b in self._byte_samples) / len(self._byte_samples)
                self._rolling_avg = avg
                if avg > 0 and bytes_per_second > avg * TRAFFIC_SPIKE_RATIO:
                    # Pass the evaluated dynamic source IP up to the alerting pipeline
                    self._fire("TRAFFIC_SPIKE", top_talker_ip,
                               f"{bytes_per_second:.0f} B/s vs avg {avg:.0f} B/s "
                               f"(×{bytes_per_second/avg:.1f})")

    # ─────────────────────── Internal ───────────────────────────────

    def _fire(self, attack_type: str, src_ip: str, detail: str):
        """Internal gatekeeper that applies cooldown throttling before raising an alert."""
        now = time.time()
        with self._cooldown_lock:
            # Check if this specific alert category is cooling down
            if now - self._last_alert_times[attack_type] < self._cooldown_period:
                return  # Quietly suppress the alert log to avoid flood noise

            # Update the cooldown timestamp barrier
            self._last_alert_times[attack_type] = now

        event = {
            "timestamp": datetime.now().isoformat(),
            "attack":    attack_type,
            "src_ip":    src_ip,
            "detail":    detail,
        }
        try:
            self.alert_callback(event)
        except Exception as e:
            log.error(f"Error in alert callback: {e}")

    def _default_alert(self, event: dict):
        log.warning(f"DEFAULT ALERT: {json.dumps(event)}")