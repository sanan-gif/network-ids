"""
IDS Packet Sniffer — uses Scapy to capture live traffic.
Requires root / CAP_NET_RAW privileges.
"""

import time
import threading
import logging
from collections import defaultdict  # Added for tracking per-IP traffic distribution

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
        self._byte_window: list = []    # list of (timestamp, src_ip, pkt_len)
        self._bw_lock  = threading.Lock()

    def start(self):
        """Start sniffing in a background thread."""
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

        # Start the background bandwidth calculation thread
        threading.Thread(target=self._bandwidth_monitor, daemon=True).start()

    def stop(self):
        """Stop the sniffing thread."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def join(self):
        if self._thread:
            self._thread.join()

    def _run(self):
        """Internal sniffer execution."""
        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                stop_filter=lambda p: self._stop.is_set(),
                store=False
            )
        except Exception as e:
            log.error(f"Sniffer error: {e}")

    def _process_packet(self, pkt):
        """Callback executed for every sniffed packet."""
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        pkt_len = len(pkt)

        # 1. Bandwidth tracking: log the packet metadata including source IP
        with self._bw_lock:
            self._byte_window.append((time.time(), src_ip, pkt_len))

        # 2. Ping Flood detection: extract ICMP
        if pkt.haslayer(ICMP):
            icmp_type = pkt[ICMP].type
            if icmp_type == 8:  # Echo Request
                self.detector.check_ping_flood(src_ip)
            return

        # 3. Port Scan & Brute Force detection: extract TCP
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
                recent = [(t, ip, b) for t, ip, b in self._byte_window if now - t < 1.0]
                self._byte_window = recent
                
                # Calculate grand total bandwidth in this window
                total = sum(b for _, _, b in recent)
                
                # Group bytes by their source IP to attribute the spike source
                ip_distribution = defaultdict(int)
                for _, ip, b in recent:
                    ip_distribution[ip] += b

            # Analyze the top talker in this window
            top_talker = "N/A"
            if ip_distribution:
                culprit_ip = max(ip_distribution, key=ip_distribution.get)
                # Identify them if they are responsible for more than 50% of the window's traffic
                if ip_distribution[culprit_ip] > (total * 0.5):
                    top_talker = culprit_ip

            # Pass both overall bytes and the top talker IP to the detector
            self.detector.check_traffic_spike(float(total), top_talker)


def _port_to_service(port: int) -> str:
    return {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC"}.get(port, "UNK")