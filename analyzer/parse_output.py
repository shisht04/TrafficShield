#!/usr/bin/env python3
"""
parse_output.py
---------------
Runs the C++ DPI engine on a .pcap file, captures its stdout,
and parses the text report into a structured JSON file (report.json).

Usage:
    python analyzer/parse_output.py <pcap_file> [options]

Options:
    --block-app <AppName>       Block an application (e.g. YouTube, TikTok)
    --block-domain <domain>     Block a domain substring (e.g. facebook)
    --block-ip <ip>             Block a source IP address
    --engine <path>             Path to compiled dpi_engine binary (default: ./dpi_engine/dpi_engine)
    --output <pcap>             Output filtered pcap path (default: output_filtered.pcap)
"""

import subprocess
import sys
import re
import json
import argparse
import os
from datetime import datetime


# ── CLI args ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Run DPI engine and produce report.json")
    parser.add_argument("pcap", help="Input .pcap file")
    parser.add_argument("--block-app",    action="append", default=[], metavar="APP",    dest="block_apps")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN", dest="block_domains")
    parser.add_argument("--block-ip",     action="append", default=[], metavar="IP",     dest="block_ips")
    parser.add_argument("--engine",  default="dpi_engine.exe", help="Path to compiled dpi_engine binary")
    parser.add_argument("--output",  default="output_filtered.pcap",    help="Output filtered pcap path")
    return parser.parse_args()


# ── Run the engine ───────────────────────────────────────────────────────────

def run_engine(args):
    if not os.path.exists(args.engine):
        print(f"[ERROR] DPI engine binary not found at: {args.engine}")
        print("  Build it first: see README.md Step 1")
        sys.exit(1)

    if not os.path.exists(args.pcap):
        print(f"[ERROR] PCAP file not found: {args.pcap}")
        sys.exit(1)

    cmd = [args.engine, args.pcap, args.output]
    for app in args.block_apps:
        cmd += ["--block-app", app]
    for domain in args.block_domains:
        cmd += ["--block-domain", domain]
    for ip in args.block_ips:
        cmd += ["--block-ip", ip]

    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True)

    if result.returncode != 0:
        print(f"[ERROR] Engine exited with code {result.returncode}")
        print(result.stderr)
        sys.exit(1)

    return (result.stdout + result.stderr).decode(errors="ignore")  # engine may print to either


# ── Parse the text report ────────────────────────────────────────────────────

def parse_report(raw_output: str, args) -> dict:
    report = {
        "meta": {
            "pcap_file":    args.pcap,
            "generated_at": datetime.now().isoformat(),
            "block_rules": {
                "apps":    args.block_apps,
                "domains": args.block_domains,
                "ips":     args.block_ips,
            }
        },
        "summary": {
            "total_packets": 0,
            "total_bytes":   0,
            "tcp_packets":   0,
            "udp_packets":   0,
            "forwarded":     0,
            "dropped":       0,
        },
        "app_breakdown": [],   # [{name, count, percent, blocked}]
        "detected_domains": [], # [{domain, app}]
        "thread_stats": [],    # [{name, count}]
        "alerts": [],          # [{type, value, reason}]
        "raw_output": raw_output,
    }

    lines = raw_output.splitlines()

    # ── Summary numbers ──────────────────────────────────────────────────────
    patterns = {
        "total_packets": r"Total Packets[:\s]+(\d+)",
        "total_bytes":   r"Total Bytes[:\s]+(\d+)",
        "tcp_packets":   r"TCP Packets[:\s]+(\d+)",
        "udp_packets":   r"UDP Packets[:\s]+(\d+)",
        "forwarded":     r"Forwarded[:\s]+(\d+)",
        "dropped":       r"Dropped[:\s]+(\d+)",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, raw_output, re.IGNORECASE)
        if m:
            report["summary"][key] = int(m.group(1))

    # ── App breakdown ────────────────────────────────────────────────────────
    # Matches lines like: ║ YouTube   4   5.2% # (BLOCKED)
    app_pattern = re.compile(
        r"║\s+([\w\-/]+)\s+(\d+)\s+([\d.]+)%.*?(BLOCKED)?", re.IGNORECASE
    )
    skip_keywords = {"total", "forwarded", "dropped", "tcp", "udp", "bytes", "packets", "thread"}

    for line in lines:
        m = app_pattern.search(line)
        if m:
            name = m.group(1).strip()
            if name.lower() in skip_keywords:
                continue
            report["app_breakdown"].append({
                "name":    name,
                "count":   int(m.group(2)),
                "percent": float(m.group(3)),
                "blocked": bool(m.group(4)),
            })

    # ── Detected domains / SNIs ──────────────────────────────────────────────
    # Matches: - www.youtube.com -> YouTube
    domain_pattern = re.compile(r"-\s+([\w.\-]+)\s+->\s+(\w+)")
    for line in lines:
        m = domain_pattern.search(line)
        if m:
            report["detected_domains"].append({
                "domain": m.group(1),
                "app":    m.group(2),
            })

    # ── Thread statistics ────────────────────────────────────────────────────
    # Matches: LB0 dispatched: 53  /  FP0 processed: 53
    thread_pattern = re.compile(r"(LB\d+|FP\d+)\s+(dispatched|processed)[:\s]+(\d+)", re.IGNORECASE)
    for line in lines:
        m = thread_pattern.search(line)
        if m:
            report["thread_stats"].append({
                "name":  m.group(1),
                "type":  m.group(2),
                "count": int(m.group(3)),
            })

    # ── Alerts (blocked rules that fired) ────────────────────────────────────
    # Lines like: [Rules] Blocked app: YouTube
    rules_pattern = re.compile(r"\[Rules\]\s+Blocked\s+(\w+):\s+(.+)", re.IGNORECASE)
    for line in lines:
        m = rules_pattern.search(line)
        if m:
            report["alerts"].append({
                "type":   m.group(1),
                "value":  m.group(2).strip(),
                "reason": "matched block rule",
            })

    # If engine not available, inject demo data so the dashboard still works
    if report["summary"]["total_packets"] == 0:
        _inject_demo_data(report, args)

    return report


def _inject_demo_data(report, args):
    """Fallback demo data when engine binary is unavailable (for testing the dashboard)."""
    print("[!] No engine output parsed — injecting demo data for dashboard preview.")
    report["summary"] = {
        "total_packets": 120,
        "total_bytes":   95400,
        "tcp_packets":   104,
        "udp_packets":   16,
        "forwarded":     97,
        "dropped":       23,
    }
    report["app_breakdown"] = [
        {"name": "HTTPS",    "count": 45, "percent": 37.5, "blocked": False},
        {"name": "YouTube",  "count": 22, "percent": 18.3, "blocked": True},
        {"name": "Google",   "count": 18, "percent": 15.0, "blocked": False},
        {"name": "Facebook", "count": 14, "percent": 11.7, "blocked": True},
        {"name": "DNS",      "count": 10, "percent": 8.3,  "blocked": False},
        {"name": "Unknown",  "count": 7,  "percent": 5.8,  "blocked": False},
        {"name": "GitHub",   "count": 4,  "percent": 3.3,  "blocked": False},
    ]
    report["detected_domains"] = [
        {"domain": "www.youtube.com",  "app": "YouTube"},
        {"domain": "www.facebook.com", "app": "Facebook"},
        {"domain": "www.google.com",   "app": "Google"},
        {"domain": "github.com",       "app": "GitHub"},
        {"domain": "dns.google",       "app": "DNS"},
        {"domain": "api.instagram.com","app": "Instagram"},
    ]
    report["alerts"] = [
        {"type": "app",    "value": app,    "reason": "matched block rule"}
        for app in args.block_apps
    ] + [
        {"type": "domain", "value": domain, "reason": "matched block rule"}
        for domain in args.block_domains
    ]
    if not report["alerts"]:
        report["alerts"] = [
            {"type": "app",    "value": "YouTube",  "reason": "matched block rule"},
            {"type": "app",    "value": "Facebook", "reason": "matched block rule"},
            {"type": "domain", "value": "tiktok",   "reason": "matched block rule"},
        ]


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # Try to run engine; fall back to demo if binary missing
    if os.path.exists(args.engine):
        raw = run_engine(args)
    else:
        print(f"[!] Engine not found at '{args.engine}'. Using demo data.")
        raw = ""

    report = parse_report(raw, args)

    out_path = "report.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Report saved to {out_path}")
    print(f"    Total packets : {report['summary']['total_packets']}")
    print(f"    Forwarded     : {report['summary']['forwarded']}")
    print(f"    Dropped       : {report['summary']['dropped']}")
    print(f"    Apps detected : {len(report['app_breakdown'])}")
    print(f"    Domains found : {len(report['detected_domains'])}")


if __name__ == "__main__":
    main()
