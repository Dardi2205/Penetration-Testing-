# DardiScan 🔍
> A powerful API & Web Penetration Testing Framework built with Python and PyQt5

![Python](https://img.shields.io/badge/Python-3.x-blue)
![PyQt5](https://img.shields.io/badge/PyQt5-Desktop-green)
![License](https://img.shields.io/badge/License-MIT-red)

## Features

### 🔍 Recon & Asset Discovery
- Subdomain enumeration via **Subfinder**
- Full pipeline: **ShuffleDNS → Alterx → DNSx → Naabu → httpx**
- Port scanning with **Naabu**
- Subdomain takeover detection via **Subzy**

### ⚡ API Testing
- Endpoint discovery with 80+ built-in wordlist
- Method tampering (GET, POST, PUT, DELETE, PATCH)
- **CORS misconfiguration** detection
- **IDOR Scanner** with baseline comparison
- **JWT Analyzer** + alg:none attack generation
- Parameter fuzzing (Arjun-style) with wordlist import

### 🛡 Vulnerability Scanner
- **Nuclei** integration (full template scan)
- **Dirsearch** with custom status code filtering
- Custom extension selection (.php, .js, .env, .sql, .bak...)
- Custom wordlist import (SecLists compatible)

### 🌐 OSINT & Passive Intelligence
- **crt.sh** certificate transparency lookup
- **DNS & Whois** reconnaissance
- **Shodan** API integration
- **Google Dorking** — auto-generate 20+ dorks and open in browser

### 📊 Dashboard & Reporting
- SQLite database — stores targets, subdomains, endpoints, vulnerabilities
- Real-time dashboard with Critical/High severity alerts
- Export results as **JSON** or **CSV**
- Live terminal console with color-coded output

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/dardiscan.git
cd dardiscan
pip3 install PyQt5 requests --break-system-packages
```

## Required Tools
```bash
# Install via pdtm
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install-all

# Or manually
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/lc/subzy@latest
pip3 install dirsearch --break-system-packages
```

## Usage
```bash
python3 main.py
```


## Disclaimer
> This tool is intended for authorized penetration testing and security research only.
> The author is not responsible for any misuse or damage caused by this tool.
