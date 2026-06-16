#!/bin/bash
# IDS Quick Install Script
# Run: bash install.sh

set -e

echo "╔══════════════════════════════════════════╗"
echo "║   Network IDS — Installation Script     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 not found. Install it first."
    exit 1
fi

echo "[1/3] Installing Python dependencies..."
pip install scapy flask --break-system-packages 2>/dev/null || \
pip install scapy flask

echo "[2/3] Creating logs directory..."
mkdir -p logs

echo "[3/3] Making main.py executable..."
chmod +x main.py

echo ""
echo "✅ Installation complete!"
echo ""
echo "Run the IDS:"
echo "  Demo mode   →  python3 main.py --demo --dashboard"
echo "  Live mode   →  sudo python3 main.py --dashboard"
echo ""
echo "Dashboard URL → http://localhost:5000"
