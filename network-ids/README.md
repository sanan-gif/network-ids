# 🛡 Network Intrusion Detection System (IDS)

A lightweight Python-based IDS for Linux that detects common network attacks in real time.

**Course:** Information Security Lab  
**Authors:** Muhammad Sanan (41250) & Muhammad Abbas (41055)  
**Instructor:** Mr. Sulman Asif Cheema  

---

## Features

| Attack | Detection Method |
|---|---|
| Port Scan | ≥20 unique ports contacted within 5 seconds |
| Ping Flood | ≥100 ICMP echo-requests per second |
| Brute Force | ≥5 failed login attempts in 60 seconds (SSH/FTP/RDP) |
| Traffic Spike | Current bandwidth > 2× 60-second rolling average |

- Real-time terminal alerts with color coding
- JSON log file (`logs/ids_alerts.json`)
- Web dashboard at `http://localhost:5000`
- Demo mode (no root needed, simulates attacks)

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/network-ids.git
cd network-ids
```

### 2. Install dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

> On Kali/Ubuntu you may need `sudo apt install python3-scapy` as well.

---

## Usage

### Demo mode (no root, simulates attacks)

```bash
python3 main.py --demo
```

### Demo mode + web dashboard

```bash
python3 main.py --demo --dashboard
```
Then open: [http://localhost:5000](http://localhost:5000)

### Live capture (requires root)

```bash
sudo python3 main.py
```

### Live capture on a specific interface

```bash
sudo python3 main.py -i eth0
```

### Live capture + dashboard

```bash
sudo python3 main.py --dashboard
```

---

## Project Structure

```
network-ids/
├── main.py                  # Entry point
├── requirements.txt
├── README.md
├── ids/
│   ├── __init__.py
│   ├── detector.py          # Attack detection logic
│   ├── sniffer.py           # Scapy packet capture
│   ├── alerter.py           # Terminal alert formatting
│   └── logger.py            # JSON log file writer
├── dashboard/
│   ├── app.py               # Flask web app
│   └── templates/
│       └── index.html       # Dashboard UI
└── logs/
    └── ids_alerts.json      # Auto-created at runtime
```

---

## Detection Thresholds

Edit `ids/detector.py` to tune thresholds:

```python
PORT_SCAN_THRESHOLD   = 20      # ports in 5 seconds
PORT_SCAN_WINDOW      = 5       # seconds
PING_FLOOD_THRESHOLD  = 100     # ICMP packets/second
BRUTE_FORCE_THRESHOLD = 5       # failed attempts
BRUTE_FORCE_WINDOW    = 60      # seconds
TRAFFIC_SPIKE_RATIO   = 2.0     # multiplier above average
```

---

## Testing the IDS

Use these tools on a second machine or in a lab environment:

| Attack | Tool |
|---|---|
| Port Scan | `nmap -sS <target_ip>` |
| Ping Flood | `hping3 --icmp --flood <target_ip>` |
| SSH Brute Force | `hydra -l root -P wordlist.txt ssh://<target_ip>` |
| Traffic Flood | `iperf3 -c <target_ip>` |

---

## License

MIT License — for educational use.
