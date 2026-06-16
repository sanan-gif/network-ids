"""
IDS Dashboard — lightweight Flask web UI.
Run: python dashboard/app.py
Access: http://localhost:5000
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, jsonify
from ids.logger import read_events, clear_log
from collections import Counter

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    events = read_events(200)
    return jsonify(events)


@app.route("/api/stats")
def api_stats():
    events = read_events(200)
    counts = Counter(e["attack"] for e in events)
    top_ips = Counter(e["src_ip"] for e in events if e.get("src_ip") != "N/A")
    return jsonify({
        "total":     len(events),
        "by_type":   dict(counts),
        "top_ips":   dict(top_ips.most_common(10)),
    })


@app.route("/api/clear", methods=["POST"])
def api_clear():
    clear_log()
    return jsonify({"status": "cleared"})


if __name__ == "__main__":
    print("Starting IDS Dashboard at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
