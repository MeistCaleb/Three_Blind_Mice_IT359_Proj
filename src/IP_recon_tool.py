#!/usr/bin/env python3
"""
ip_recon_v1_geolocation.py - IP Geolocation
Usage: python3 ip_recon_v1_geolocation.py <IP_ADDRESS>

Python packages: requests, rich
Install: pip install requests rich
"""

import argparse
import re
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
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def validate_ip(ip: str) -> bool:
    pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if not pattern.match(ip):
        return False
    return all(0 <= int(o) <= 255 for o in ip.split("."))


# ══════════════════════════════════════════════════════════════════════════════
# Geolocation
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
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="IP Geolocation Lookup")
    parser.add_argument("ip", help="Target IP address")
    args = parser.parse_args()

    if not validate_ip(args.ip):
        console.print(f"[bold red][ERROR] Invalid IP address: {args.ip}[/bold red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold]Target[/bold] : [cyan]{args.ip}[/cyan]\n"
        f"[bold]Time[/bold]   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold white]IP RECON  v1 — Geolocation[/bold white]",
        border_style="cyan",
    ))

    console.print("[dim]Running geolocation lookup...[/dim]")
    geo = lookup_ipapi(args.ip)

    findings = {
        "target":      args.ip,
        "scanned_at":  datetime.now().isoformat(),
        "geolocation": geo,
    }

    console.print(Rule("[bold green]Results[/bold green]"))
    console.print(json.dumps(findings, indent=2))
    console.print(Rule("[bold green]Done[/bold green]"))


if __name__ == "__main__":
    main()
