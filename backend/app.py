#!/usr/bin/env python3
"""
app.py  —  Flask backend for the Network Security Dashboard
------------------------------------------------------------
Serves the parsed DPI report as a REST API and hosts the dashboard.

Endpoints:
    GET /              → dashboard HTML
    GET /api/report    → full report.json as JSON
    GET /api/summary   → just the summary stats
    POST /api/analyze  → trigger a fresh analysis (reruns the parser)

Run:
    python backend/app.py
    → http://localhost:5000
"""

import json
import os
import subprocess
import sys
from flask import Flask, jsonify, send_from_directory, request, abort

app = Flask(__name__, static_folder=None)

# Paths (relative to project root)
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_PATH   = os.path.join(BASE_DIR, "report.json")
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
ANALYZER      = os.path.join(BASE_DIR, "analyzer", "parse_output.py")
SAMPLE_PCAP   = os.path.join(BASE_DIR, "sample_data", "test_dpi.pcap")


# ── Helper ────────────────────────────────────────────────────────────────────

def load_report():
    if not os.path.exists(REPORT_PATH):
        # Auto-generate with demo data if not present
        subprocess.run(
            [sys.executable, ANALYZER, SAMPLE_PCAP],
            cwd=BASE_DIR
        )
    if not os.path.exists(REPORT_PATH):
        return None
    with open(REPORT_PATH) as f:
        return json.load(f)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    path = os.path.join(DASHBOARD_DIR, "index.html")
    if not os.path.exists(path):
        return "Dashboard not found. Make sure dashboard/index.html exists.", 404
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/api/report")
def api_report():
    """Return the full report JSON."""
    report = load_report()
    if report is None:
        return jsonify({"error": "No report found. Run analyzer/parse_output.py first."}), 404
    return jsonify(report)


@app.route("/api/summary")
def api_summary():
    """Return just the summary stats."""
    report = load_report()
    if report is None:
        return jsonify({"error": "No report found."}), 404
    return jsonify({
        "summary":    report.get("summary", {}),
        "meta":       report.get("meta", {}),
        "alert_count": len(report.get("alerts", [])),
    })


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Trigger a fresh analysis.
    Body (JSON, all optional):
        {
            "pcap": "path/to/file.pcap",
            "block_apps": ["YouTube"],
            "block_domains": ["facebook"],
            "block_ips": []
        }
    """
    body = request.get_json(silent=True) or {}
    pcap         = body.get("pcap", SAMPLE_PCAP)
    block_apps   = body.get("block_apps", [])
    block_domains= body.get("block_domains", [])
    block_ips    = body.get("block_ips", [])

    cmd = [sys.executable, ANALYZER, pcap]
    for app_name in block_apps:
        cmd += ["--block-app", app_name]
    for domain in block_domains:
        cmd += ["--block-domain", domain]
    for ip in block_ips:
        cmd += ["--block-ip", ip]

    result = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)

    if result.returncode != 0:
        return jsonify({
            "error": "Analysis failed",
            "detail": result.stderr
        }), 500

    report = load_report()
    return jsonify({
        "status": "ok",
        "summary": report.get("summary", {}) if report else {}
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "running", "report_exists": os.path.exists(REPORT_PATH)})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  🛡️  Network Security Dashboard")
    print("  http://localhost:5000")
    print("=" * 55)

    # Auto-generate report on startup if missing
    if not os.path.exists(REPORT_PATH):
        print("[*] No report.json found — generating demo data...")
        subprocess.run(
            [sys.executable, ANALYZER, SAMPLE_PCAP],
            cwd=BASE_DIR
        )

    app.run(debug=True, host="0.0.0.0", port=5000)
