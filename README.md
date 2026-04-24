# Three Blind Mice IT359 Project
# IP Recon Tool

## Team Members:
- Caleb Meister
- Nathan Sigulas
- Ryan Garland 

## Features
 
- **Geolocation** — Country, city, ISP, ASN, proxy/VPN/hosting detection via ip-api.com
- **Blacklist Checks** — AbuseIPDB, StopForumSpam, VirusTotal, Shodan, and Spamhaus (DNS-based)
- **TCP Scan** — Full or fast Nmap SYN scan with service, version, and OS detection
- **UDP Scan** — Common UDP port sweep via Masscan
- **AI Threat Summary** — Structured threat analysis streamed live from your OpenWebUI instance

## Requirements
 
### System Tools
 
| Tool | Install |
|------|---------|
| Python 3.10+ | `sudo apt install python3` |
| `nmap` | `sudo apt install nmap` |
| `masscan` | `sudo apt install masscan` |
 
### Python Packages
 
```bash
pip install requests rich
```
 
---
 
## Installation
 
**Step 1 — Clone the repository**
 
```bash
git clone https://github.com/MeistCaleb/Three_Blind_Mice_IT359_Proj.git
cd Three_Blind_Mice_IT359_Proj.git
cd src
```
 
**Step 2 — Install Python dependencies**
 
```bash
pip install requests rich
```
 
**Step 3 — Verify nmap and masscan are installed**
 
```bash
nmap --version
masscan --version
```
 
Both commands should print a version string. If either is missing, install it with `sudo apt install <tool>`.

## How to Run

```bash
sudo python3 IP_Recon_Tool.py IPAddr
```
 
---
  
