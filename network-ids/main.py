#!/usr/bin/env python3
"""
Network Intrusion Detection System (IDS)
=========================================
Authors : Muhammad Sanan (41250), Muhammad Abbas (41055)
Course  : Information Security Lab
Instructor: Mr. Sulman Asif Cheema

Usage:
  sudo python3 main.py                  # sniff on default interface
  sudo python3 main.py -i eth0          # sniff on specific interface
  sudo python3 main.py --demo           # run in demo/test mode (no root needed)
  sudo python3 main.py --dashboard      # also start the web dashboard
"""

import argparse
import sys
import time
import threading
import random
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("IDS")

from ids.detector import AttackDetector
from ids.alerter  import handle_alert


def parse_args():
    p = argparse.ArgumentParser(description="Network IDS")
    p.add_argument("-i", "--iface",     default=None,  help="Network interface (e.g. eth0)")
    p.add_argument("--demo",            action="store_true", help="Demo mode — simulate attacks")
    p.add_argument("--dashboard",       action="store_true", help="Start web dashboard on :5000")
    p.add_argument("--filter",          default="ip",  help="BPF filter (default: 'ip')")
    return p.parse_args()


def start_dashboard():
    """Run Flask dashboard in a background thread."""
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from dashboard.app import app
        t = threading.Thread(
            target=lambda: app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False),
            daemon=True
        )
        t.start()
        log.info("Dashboard started → http://localhost:5000")
    except ImportError:
        log.warning("Flask not installed. Install with: pip install flask --break-system-packages")


def demo_mode(detector: AttackDetector):
    """Simulate attack traffic without needing root or Scapy."""
    log.info("═══ DEMO MODE — simulating attack traffic ═══")
    log.info("Press Ctrl+C to stop.\n")

    fake_ips = ["192.168.1.10", "10.0.0.55", "172.16.0.3", "45.33.32.156"]

    while True:
        ip = random.choice(fake_ips)
        attack = random.choice(["portscan", "pingflood", "bruteforce", "spike"])

        if attack == "portscan":
            # Simulate 25 SYN packets to different ports
            for port in random.sample(range(1, 65535), 25):
                detector.check_port_scan(ip, port)

        elif attack == "pingflood":
            # Simulate 110 ICMP packets in burst
            for _ in range(110):
                detector.check_ping_flood(ip)

        elif attack == "bruteforce":
            # Simulate 6 failed SSH attempts
            for _ in range(6):
                detector.check_brute_force(ip, "SSH")

        elif attack == "spike":
            # Simulate traffic at 3× baseline
            detector.check_traffic_spike(0.0)   # seed average
            time.sleep(0.05)
            detector.check_traffic_spike(0.0)
            time.sleep(0.05)
            detector.check_traffic_spike(0.0)
            time.sleep(0.05)
            detector.check_traffic_spike(0.0)
            time.sleep(0.05)
            detector.check_traffic_spike(0.0)
            time.sleep(0.05)
            detector.check_traffic_spike(900000.0)  # 900 KB/s spike

        time.sleep(random.uniform(1.5, 4.0))


def live_mode(detector: AttackDetector, iface: str, bpf_filter: str):
    """Start live packet capture (requires root + Scapy)."""
    try:
        from ids.sniffer import Sniffer
    except RuntimeError as e:
        log.error(str(e))
        sys.exit(1)

    sniffer = Sniffer(detector, iface=iface, bpf_filter=bpf_filter)
    sniffer.start()
    log.info("IDS running — press Ctrl+C to stop.")
    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()


def main():
    args = parse_args()

    print("""
╔══════════════════════════════════════════════════════╗
║         NETWORK INTRUSION DETECTION SYSTEM           ║
║   Muhammad Sanan (41250) & Muhammad Abbas (41055)    ║
║              Information Security Lab                ║
╚══════════════════════════════════════════════════════╝
""")

    detector = AttackDetector(alert_callback=handle_alert)

    if args.dashboard:
        start_dashboard()

    if args.demo:
        try:
            demo_mode(detector)
        except KeyboardInterrupt:
            log.info("Demo stopped.")
    else:
        if sys.platform == "win32":
            log.error("Live capture requires Linux. Use --demo on Windows.")
            sys.exit(1)
        live_mode(detector, args.iface, args.filter)


if __name__ == "__main__":
    main()
