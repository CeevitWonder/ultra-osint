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


