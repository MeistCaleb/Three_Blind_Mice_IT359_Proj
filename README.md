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
## Configuration
 
Open `ip_recon.py` and update the values at the top of the file:
 
```python
OPENWEBUI_BASE_URL = "http://your-openwebui-host:8080"
OPENWEBUI_MODEL    = "your-model-name"
OPENWEBUI_API_KEY  = "your-openwebui-api-key"
```
 
### Blacklist API Keys
 
The following services require free API keys. If a key is not set the check is skipped and marked as such in the AI summary.
 
| Service | Environment Variable | Get a free key |
|---------|---------------------|----------------|
| AbuseIPDB | `ABUSEIPDB_KEY` | [abuseipdb.com](https://www.abuseipdb.com) |
| VirusTotal | `VIRUSTOTAL_KEY` | [virustotal.com](https://www.virustotal.com) |
| Shodan | `SHODAN_KEY` | [account.shodan.io](https://account.shodan.io) |
 
> **StopForumSpam** and **Spamhaus** require no API key and will always run automatically.
 
**Step 4 — Set your API keys**
 
Export them in your shell before running the tool:
 
```bash
export ABUSEIPDB_KEY="your_key_here"
export VIRUSTOTAL_KEY="your_key_here"
export SHODAN_KEY="your_key_here"
```
 
Or add them to a `.env` file in the project root:
 
```
ABUSEIPDB_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
SHODAN_KEY=your_key_here
```
  
