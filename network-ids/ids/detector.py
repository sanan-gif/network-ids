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
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("IDS")


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
        self._byte_samples = []          # (timestamp, bytes_per_second)
        self._ts_lock      = Lock()
        self._rolling_avg  = 0.0

    # ─────────────────── Public check methods ───────────────────────

    def check_port_scan(self, src_ip: str, dst_port: int):
        now = time.time()
        with self._ps_lock:
            ports = self._port_map[src_ip]
            # Evict old entries outside the window
            ports = {p: t for p, t in ports.items() if now - t < PORT_SCAN_WINDOW}
            ports[dst_port] = now
            self._port_map[src_ip] = ports

            if len(ports) >= PORT_SCAN_THRESHOLD:
                self._fire("PORT_SCAN", src_ip,
                           f"Contacted {len(ports)} ports in {PORT_SCAN_WINDOW}s")
                self._port_map[src_ip] = {}   # reset

    def check_ping_flood(self, src_ip: str):
        now = time.time()
        with self._pf_lock:
            times = self._icmp_times[src_ip]
            times.append(now)
            # Keep only last 1-second window
            times = [t for t in times if now - t < 1.0]
            self._icmp_times[src_ip] = times

            if len(times) >= PING_FLOOD_THRESHOLD:
                self._fire("PING_FLOOD", src_ip,
                           f"{len(times)} ICMP packets in 1 second")
                self._icmp_times[src_ip] = []   # reset

    def check_brute_force(self, src_ip: str, service: str):
        now = time.time()
        with self._bf_lock:
            times = self._bf_times[src_ip]
            times.append(now)
            times = [t for t in times if now - t < BRUTE_FORCE_WINDOW]
            self._bf_times[src_ip] = times

            if len(times) >= BRUTE_FORCE_THRESHOLD:
                self._fire("BRUTE_FORCE", src_ip,
                           f"{len(times)} failed {service} attempts in {BRUTE_FORCE_WINDOW}s")
                self._bf_times[src_ip] = []   # reset

    def check_traffic_spike(self, bytes_per_second: float):
        now = time.time()
        with self._ts_lock:
            self._byte_samples.append((now, bytes_per_second))
            # Keep 60-second history
            self._byte_samples = [(t, b) for t, b in self._byte_samples if now - t < 60]

            if len(self._byte_samples) >= 5:
                avg = sum(b for _, b in self._byte_samples) / len(self._byte_samples)
                self._rolling_avg = avg
                if avg > 0 and bytes_per_second > avg * TRAFFIC_SPIKE_RATIO:
                    self._fire("TRAFFIC_SPIKE", "N/A",
                               f"{bytes_per_second:.0f} B/s vs avg {avg:.0f} B/s "
                               f"(×{bytes_per_second/avg:.1f})")

    # ─────────────────────── Internal ───────────────────────────────

    def _fire(self, attack_type: str, src_ip: str, detail: str):
        event = {
            "timestamp": datetime.now().isoformat(),
            "attack":    attack_type,
            "src_ip":    src_ip,
            "detail":    detail,
        }
        self.alert_callback(event)

    @staticmethod
    def _default_alert(event: dict):
        log.warning("🚨 ALERT  %s | %s | %s",
                    event["attack"], event["src_ip"], event["detail"])
