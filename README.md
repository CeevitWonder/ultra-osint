# 🔍 ULTRA-COMPREHENSIVE OSINT INTELLIGENCE GATHERER v3.0

> ⚠️ **LEGAL DISCLAIMER**: This tool is for **authorized security research and educational purposes only**. Users are responsible for complying with all applicable laws. The author assumes no liability for misuse.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-26A1F0?logo=kalilinux)](https://kali.org)

A professional-grade OSINT intelligence gathering framework that collects maximum actionable intelligence with detailed version detection, vulnerability assessment, and structured reporting.

---

## ✨ Features

| Module | Capability |
|--------|-----------|
| 🌐 Target Resolution | Auto-protocol detection, IP/domain resolution, geolocation |
| 📋 WHOIS Intelligence | Registration data, expiry warnings, contact extraction |
| 🔍 DNS Enumeration | A/AAAA/MX/NS/TXT/SOA/CAA + subdomain discovery |
| 🚪 Port Scanning | System `nmap` integration with service/version detection |
| 🔒 SSL/TLS Analysis | Certificate inspection via `sslscan` + Python fallback |
| 🚀 Technology Detection | Multi-source fingerprinting via `httpx` + `webanalyze` |
| 📝 Web Content Analysis | Metadata, emails, security headers audit |
| 🌊 Shodan Integration | Host intelligence correlation (API key required) |
| 📊 Executive Reporting | Security scoring, vulnerability correlation, recommendations |

---

## 📦 Installation

### Prerequisites (Install Once)

```bash
# System packages (Debian/Kali/Ubuntu)
sudo apt update && sudo apt install -y nmap sslscan git python3-pip python3-venv

# Go binaries (install outside virtual environment)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/rverton/webanalyze/cmd/webanalyze@latest

# Add Go binaries to PATH (add to ~/.bashrc or ~/.zshrc)
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc && source ~/.bashrc

# Verify installations
which nmap httpx webanalyze sslscan


## Python Environment Setup

# Clone this repository
git clone https://github.com/YOUR_USERNAME/ultra-osint.git
cd ultra-osint

# Create and activate virtual environment
python3 -m venv osint-env
source osint-env/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

## 🚀 Quick Start

# Basic scan
python3 ultra_osint.py example.com

# Full scan with API keys and output files
python3 ultra_osint.py https://target.com \
  --shodan-api YOUR_SHODAN_KEY \
  --builtwith-key YOUR_BUILTWITH_KEY \
  -o report.txt -j data.json \
  -v  # verbose mode

# Custom port scan
python3 ultra_osint.py 192.168.1.1 --ports 22,80,443,8080,3306

## 📁 Project Structure
```
ultra-osint/
├── ultra_osint.py          # Main executable script
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── .gitignore             # Git ignore rules
├── CONTRIBUTING.md        # Contribution guidelines
├── SECURITY.md            # Security policy & responsible disclosure
└── outputs/               # Generated reports (git-ignored)
```
### ⚠️ Legal & Ethical Use
### ✅ Allowed:
Authorized penetration testing engagements
Security research on assets you own or have written permission to test
Educational purposes in controlled lab environments
Bug bounty programs (within scope rules)

### ❌ Prohibited:
Unauthorized scanning of systems you don't own
Harassment, doxxing, or illegal surveillance
Violating terms of service of any platform
Always obtain written authorization before scanning any target.

### 🤝 Contributing
Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

### 🔐 Security Policy
Found a vulnerability? Please review SECURITY.md for responsible disclosure.

### 📄 License
Distributed under the MIT License. See LICENSE for details.
Built with ❤️ for the security research community
