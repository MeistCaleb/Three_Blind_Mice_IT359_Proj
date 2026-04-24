#!/usr/bin/env python3
"""
ip_recon.py - IP Reconnaissance Tool
Usage: sudo python3 ip_recon.py <IP_ADDRESS> [--fast]

Requires: nmap, masscan (system tools)
Python packages: requests, rich
Install: pip install requests rich
"""

import argparse
import os
import re
import socket
import subprocess
import sys
import json
from datetime import datetime

try:
    import requests
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
except ImportError:
    print("[ERROR] Missing Python dependencies. Run: pip install requests rich")
    sys.exit(1)

console = Console()

# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

OPENWEBUI_BASE_URL = "http://sushi.it.ilstu.edu:8080"
OPENWEBUI_MODEL    = "qwen3-vl:235b"
OPENWEBUI_API_KEY  = "sk-1708ae0fc4c341769a6abad7af762fbf"

# Blacklist API keys — set via env vars or paste directly
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_KEY",  "6a2c3f50a238aecc9a4124c84fe61ccb723113fa6708f3648641576dfa641366be833812f0af7cd6")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_KEY", "0764e04a64239ae6ead51b6fe4b40cb3d538421370a8bec8031d1cb015e99f50")
SHODAN_API_KEY     = os.environ.get("SHODAN_KEY",     "poBKhAwoqtwEseHZMyYK7ZNm9jNYJRnN")
# Spamhaus needs no API key


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def validate_ip(ip: str) -> bool:
    pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if not pattern.match(ip):
        return False
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def check_root():
    if os.geteuid() != 0:
        console.print("[bold red][ERROR] Root privileges required (sudo).[/bold red]")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# Section 1 — Geolocation
# ══════════════════════════════════════════════════════════════════════════════

def lookup_ipapi(ip: str) -> dict:
    fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", params={"fields": fields}, timeout=10)
        data = r.json()
        return data if data.get("status") == "success" else {}
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# Section 2 — Blacklists
# ══════════════════════════════════════════════════════════════════════════════

def lookup_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"skipped": True, "reason": "No API key — set ABUSEIPDB_KEY"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        return r.json().get("data", {})
    except Exception as e:
        return {"error": str(e)}


def lookup_stopforumspam(ip: str) -> dict:
    try:
        r = requests.get("https://api.stopforumspam.org/api", params={"ip": ip, "json": 1}, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def lookup_virustotal(ip: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"skipped": True, "reason": "No API key — set VIRUSTOTAL_KEY"}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", None)
        return {
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "reputation":  reputation,
        }
    except Exception as e:
        return {"error": str(e)}


def lookup_shodan(ip: str) -> dict:
    if not SHODAN_API_KEY:
        return {"skipped": True, "reason": "No API key — set SHODAN_KEY"}
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
            timeout=10,
        )
        if r.status_code == 404:
            return {"found": False}
        data = r.json()
        return {
            "found":      True,
            "org":        data.get("org"),
            "isp":        data.get("isp"),
            "os":         data.get("os"),
            "ports":      data.get("ports", []),
            "vulns":      list(data.get("vulns", {}).keys()),
            "tags":       data.get("tags", []),
            "hostnames":  data.get("hostnames", []),
            "domains":    data.get("domains", []),
        }
    except Exception as e:
        return {"error": str(e)}


def lookup_spamhaus(ip: str) -> dict:
    """DNS-based Spamhaus blocklist check — no API key needed."""
    # Reverse the IP for DNS lookup
    reversed_ip = ".".join(reversed(ip.split(".")))
    lists = {
        "SBL":  f"{reversed_ip}.sbl.spamhaus.org",   # Spammer IPs
        "XBL":  f"{reversed_ip}.xbl.spamhaus.org",   # Exploits / botnets
        "PBL":  f"{reversed_ip}.pbl.spamhaus.org",   # Policy block (end-user IPs)
        "DBL":  f"{reversed_ip}.dbl.spamhaus.org",   # Domain block
        "ZEN":  f"{reversed_ip}.zen.spamhaus.org",   # Combined SBL+XBL+PBL
    }
    results = {}
    for name, host in lists.items():
        try:
            socket.gethostbyname(host)
            results[name] = "LISTED"
        except socket.gaierror:
            results[name] = "not listed"
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Section 3 — Nmap TCP
# ══════════════════════════════════════════════════════════════════════════════

def run_nmap(ip: str, fast: bool = False) -> list[dict]:
    if fast:
        cmd = ["nmap", "-sS", "-sV", "-sC", "--open", "-T4", "-oG", "-", ip]
    else:
        cmd = ["nmap", "-sS", "-sV", "-sC", "-O", "-p-", "--min-rate", "1000", "--open", "-T4", "-oG", "-", ip]

    open_ports = []
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in process.stdout:
            line = line.rstrip()
            if "/open/" in line:
                for part in line.split():
                    if "/open/" in part:
                        parts = part.split("/")
                        open_ports.append({
                            "port":    parts[0] if len(parts) > 0 else "—",
                            "proto":   parts[1] if len(parts) > 1 else "—",
                            "state":   parts[2] if len(parts) > 2 else "—",
                            "service": parts[4] if len(parts) > 4 else "—",
                        })
        process.wait()
    except FileNotFoundError:
        return [{"error": "nmap not found"}]

    return open_ports


# ══════════════════════════════════════════════════════════════════════════════
# Section 4 — Masscan UDP
# ══════════════════════════════════════════════════════════════════════════════

def run_masscan(ip: str) -> list[dict]:
    udp_ports = "53,67,68,69,111,123,137,138,161,162,500,514,520,1194,1900,4500,5353,5355"
    cmd = ["masscan", "--ports", f"U:{udp_ports}", "--rate", "1000", ip]

    open_ports = []
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in process.stdout:
            line = line.rstrip()
            if "Discovered open port" in line:
                parts      = line.split()
                port_proto = parts[4] if len(parts) > 4 else "—/—"
                host       = parts[6] if len(parts) > 6 else "—"
                port, proto = port_proto.split("/") if "/" in port_proto else (port_proto, "—")
                open_ports.append({"port": port, "proto": proto.upper(), "ip": host})
        process.wait()
    except FileNotFoundError:
        return [{"error": "masscan not found"}]

    return open_ports


# ══════════════════════════════════════════════════════════════════════════════
# OpenWebUI AI Summary
# ══════════════════════════════════════════════════════════════════════════════

def ai_summary(findings: dict):
    console.print(Rule("[bold magenta]AI Analysis  —  qwen3-vl:235b via OpenWebUI[/bold magenta]"))

    prompt = f"""You are a cybersecurity analyst. Below are the results of an IP reconnaissance scan.
Provide a concise, structured threat summary covering:
1. Who owns this IP and where it is located
2. Open TCP ports and what services/risks they imply
3. Open UDP ports and what services/risks they imply
4. Blacklist / reputation status across all sources checked
5. Overall risk assessment (Low / Medium / High) with a brief justification

Findings (JSON):
{json.dumps(findings, indent=2)}
"""

    url     = f"{OPENWEBUI_BASE_URL}/api/chat/completions"
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {OPENWEBUI_API_KEY}",
    }
    payload = {
        "model":    OPENWEBUI_MODEL,
        "stream":   True,
        "messages": [{"role": "user", "content": prompt}],
    }

    try:
        with requests.post(url, headers=headers, json=payload, stream=True, timeout=120) as r:
            r.raise_for_status()
            for raw_line in r.iter_lines():
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8")
                if line.startswith("data: "):
                    line = line[6:]
                if line.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(line)
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    text  = delta.get("content", "")
                    if text:
                        console.print(text, end="")
                except json.JSONDecodeError:
                    continue
        console.print("\n")

    except requests.exceptions.ConnectionError:
        console.print(f"  [red]Could not connect to OpenWebUI at {OPENWEBUI_BASE_URL}[/red]")
        console.print("  [dim]Check that your instance is running and reachable.[/dim]\n")
    except requests.exceptions.HTTPError as e:
        console.print(f"  [red]HTTP error from OpenWebUI: {e}[/red]\n")
    except Exception as e:
        console.print(f"  [red]Unexpected error: {e}[/red]\n")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="IP Reconnaissance — Nmap TCP + Masscan UDP + IP Intelligence + AI Summary"
    )
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--fast", action="store_true",
                        help="Scan top 1000 TCP ports instead of all 65535")
    args = parser.parse_args()

    if not validate_ip(args.ip):
        console.print(f"[bold red][ERROR] Invalid IP address: {args.ip}[/bold red]")
        sys.exit(1)

    check_root()

    console.print(Panel(
        f"[bold]Target[/bold] : [cyan]{args.ip}[/cyan]\n"
        f"[bold]Time[/bold]   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[bold]Mode[/bold]   : {'Fast (top 1000)' if args.fast else 'Full (-p-)'}\n"
        f"[bold]Model[/bold]  : {OPENWEBUI_MODEL}  [dim]({OPENWEBUI_BASE_URL})[/dim]",
        title="[bold white]IP RECONNAISSANCE[/bold white]",
        border_style="cyan",
    ))

    console.print("[dim]Running geolocation lookup...[/dim]")
    geo = lookup_ipapi(args.ip)

    console.print("[dim]Checking AbuseIPDB...[/dim]")
    abuse = lookup_abuseipdb(args.ip)

    console.print("[dim]Checking StopForumSpam...[/dim]")
    sfs = lookup_stopforumspam(args.ip)

    console.print("[dim]Checking VirusTotal...[/dim]")
    vt = lookup_virustotal(args.ip)

    console.print("[dim]Checking Shodan...[/dim]")
    shodan = lookup_shodan(args.ip)

    console.print("[dim]Checking Spamhaus (DNS)...[/dim]")
    spamhaus = lookup_spamhaus(args.ip)

    console.print("[dim]Running Nmap TCP scan...[/dim]")
    tcp_ports = run_nmap(args.ip, fast=args.fast)

    console.print("[dim]Running Masscan UDP scan...[/dim]")
    udp_ports = run_masscan(args.ip)

    findings = {
        "target":         args.ip,
        "scanned_at":     datetime.now().isoformat(),
        "geolocation":    geo,
        "blacklists": {
            "abuseipdb":     abuse,
            "stopforumspam": sfs,
            "virustotal":    vt,
            "shodan":        shodan,
            "spamhaus":      spamhaus,
        },
        "open_tcp_ports": tcp_ports,
        "open_udp_ports": udp_ports,
    }

    ai_summary(findings)

    console.print(Rule("[bold green]Done[/bold green]"))


if __name__ == "__main__":
    main()
