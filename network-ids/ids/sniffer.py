"""
IDS Packet Sniffer — uses Scapy to capture live traffic.
Requires root / CAP_NET_RAW privileges.
"""

import time
import threading
import logging

log = logging.getLogger("IDS.sniffer")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    log.warning("Scapy not installed. Live capture disabled. "
                "Run: pip install scapy --break-system-packages")


# SSH/FTP destination ports used to flag brute-force candidates
BRUTE_FORCE_PORTS = {22, 21, 23, 3389, 5900}  # SSH, FTP, Telnet, RDP, VNC

# Track TCP SYN→ACK pairs to detect failed logins (simplified heuristic)
# A RST or no-ACK response after SYN on BF ports = failed attempt
_syn_tracker: dict = {}   # (src_ip, dst_port) → timestamp


class Sniffer:
    def __init__(self, detector, iface: str = None, bpf_filter: str = "ip"):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for live sniffing.")
        self.detector  = detector
        self.iface     = iface          # None → Scapy picks default
        self.bpf_filter = bpf_filter
        self._stop     = threading.Event()
        self._thread   = None

        # Bandwidth tracking
        self._byte_window: list = []    # list of (timestamp, pkt_len)
        self._bw_lock = threading.Lock()
        self._bw_thread = threading.Thread(target=self._bandwidth_monitor,
                                           daemon=True)

    # ─────────────────────── Public API ──────────────────────────────

    def start(self):
        log.info("Starting sniffer on interface: %s", self.iface or "default")
        self._bw_thread.start()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        log.info("Sniffer stopped.")

    def join(self):
        if self._thread:
            self._thread.join()

    # ─────────────────────── Internals ───────────────────────────────

    def _run(self):
        sniff(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def _process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        pkt_len = len(pkt)

        # ── Bandwidth tracking ──
        with self._bw_lock:
            self._byte_window.append((time.time(), pkt_len))

        # ── ICMP → Ping Flood ──
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:   # Echo Request
            self.detector.check_ping_flood(src_ip)

        # ── TCP ──
        if pkt.haslayer(TCP):
            tcp   = pkt[TCP]
            flags = tcp.flags

            # Port scan: SYN-only packets to varying ports
            if flags == "S":   # SYN without ACK
                self.detector.check_port_scan(src_ip, tcp.dport)
                # Track for brute-force detection
                if tcp.dport in BRUTE_FORCE_PORTS:
                    _syn_tracker[(src_ip, tcp.dport)] = time.time()

            # Brute force: RST response to a tracked SYN (connection refused / failed auth)
            if flags & 0x04:   # RST flag set
                key = (src_ip, tcp.sport)
                if key in _syn_tracker:
                    port = tcp.sport
                    service = _port_to_service(port)
                    self.detector.check_brute_force(src_ip, service)
                    del _syn_tracker[key]

    def _bandwidth_monitor(self):
        """Every second, compute bytes/s and feed traffic spike detector."""
        while not self._stop.is_set():
            time.sleep(1)
            now = time.time()
            with self._bw_lock:
                # Keep only packets from the last 1 second
                recent = [(t, b) for t, b in self._byte_window if now - t < 1.0]
                self._byte_window = recent
                total = sum(b for _, b in recent)
            self.detector.check_traffic_spike(float(total))


def _port_to_service(port: int) -> str:
    return {22: "SSH", 21: "FTP", 23: "Telnet",
            3389: "RDP", 5900: "VNC"}.get(port, f"port-{port}")
