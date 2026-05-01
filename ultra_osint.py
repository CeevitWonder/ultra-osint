#!/home/kali/osint-env/bin/python
"""
ULTRA-COMPREHENSIVE OSINT INTELLIGENCE GATHERER v3.0
Collects maximum actionable intelligence with detailed version detection and vulnerability assessment

CHANGES IN v3.0:
✅ webanalyze: Subprocess + JSON parsing (Go binary - external to venv)
✅ httpx: Subprocess with user-specified command format
✅ nmap: System binary via subprocess (NOT python-nmap library)
✅ REMOVED: python-Wappalyzer dependency entirely
✅ COMPATIBLE: Python virtual environments (osint-env)
✅ ROBUST: Binary detection, error handling, timeout management
✅ OUTPUT: Structured JSON + human-readable reports

USAGE:
  python3 ultra_osint.py example.com
  python3 ultra_osint.py https://target.com -j data.json -o report.txt --shodan-api KEY

EXTERNAL BINARIES REQUIRED (install outside venv):
  • nmap: apt install nmap | brew install nmap
  • httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  • webanalyze: go install github.com/rverton/webanalyze/cmd/webanalyze@latest
  • sslscan: apt install sslscan | brew install sslscan
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import warnings
import subprocess
import re
import platform as platform_module
import shutil
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, urljoin
from io import BytesIO

# Python packages (install via pip in venv)
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
import dns.reversename
from shodan import Shodan
from shodan.exception import APIError
import builtwith
from PIL import Image

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore', message='.*Unverified HTTPS request.*')
warnings.filterwarnings('ignore', category=DeprecationWarning)

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
DEFAULT_TIMEOUT = 30
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# ============================================================================
# EXTERNAL BINARY MANAGEMENT (Go/C binaries - NOT Python packages)
# ============================================================================

def check_binary_available(binary_name, version_flag='-version'):
    """
    Check if external binary exists, is executable, and responds to version check.
    
    Returns: (bool, str) tuple: (is_available, status_message)
    """
    path = shutil.which(binary_name)
    if not path:
        return False, f"Binary '{binary_name}' not found in PATH"
    
    try:
        # Handle tool-specific version flags
        if binary_name == 'sslscan':
            version_flag = '--version'
        elif binary_name == 'nmap':
            version_flag = '-V'
        
        result = subprocess.run(
            [binary_name, version_flag],
            capture_output=True, timeout=5, text=True, check=False
        )
        
        if result.returncode == 0:
            # Extract version string from output
            version = 'unknown'
            output_lines = (result.stdout or result.stderr).strip().split('\n')
            for line in output_lines:
                if 'version' in line.lower() or binary_name.lower() in line.lower():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        version = parts[-1].strip('()vV')
                        break
            return True, f"v{version}"
        return False, f"Version check failed (exit code {result.returncode})"
        
    except subprocess.TimeoutExpired:
        return False, "Version check timed out"
    except FileNotFoundError:
        return False, "Binary not found in PATH"
    except Exception as e:
        return False, f"Check error: {type(e).__name__}"


# Pre-check all required binaries at module load
REQUIRED_BINARIES = {
    'nmap': ('nmap', '-V'),
    'httpx': ('httpx', '-version'),
    'webanalyze': ('webanalyze', '-help'),
    'sslscan': ('sslscan', '--version'),
    'whatweb': ('whatweb', '--version'),  # Optional
}

BINARY_STATUS = {}
for key, (binary, flag) in REQUIRED_BINARIES.items():
    available, version_info = check_binary_available(binary, flag)
    BINARY_STATUS[key] = {
        'available': available,
        'version': version_info if available else None,
        'path': shutil.which(binary) if available else None
    }


# ============================================================================
# EXTERNAL TOOL WRAPPERS (Subprocess execution with JSON parsing)
# ============================================================================

def run_httpx_scan(target_url, timeout=30, follow_redirects=True, verbose=False):
    """
    Execute httpx CLI with user-specified command format.
    Returns: dict with parsed results + raw output, or None on failure
    """
    if not BINARY_STATUS.get('httpx', {}).get('available'):
        return None
    
    try:
        # Ensure URL has scheme for httpx
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = f"https://{target_url}"
        
        # FIXED: Correct httpx command format (removed invalid -u flag placement)
        # User's format: echo "example.com" | httpx -silent -title -status-code -tech-detect -follow-redirects
        redirect_flag = '-follow-redirects' if follow_redirects else '-no-follow-redirects'
        cmd = f'echo "{target_url}" | httpx -silent -title -status-code -tech-detect {redirect_flag} -json'
        
        if verbose:
            print(f"   🔄 Executing: {cmd}")
        
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            executable='/bin/bash' if platform_module.system() != 'Windows' else None
        )
        
        # FIXED: Always capture and return raw output for debugging/reporting
        raw_output = {
            'stdout': result.stdout.strip()[:10000] if result.stdout else '',  # Truncate for safety
            'stderr': result.stderr.strip()[:2000] if result.stderr else '',
            'returncode': result.returncode,
            'command': cmd
        }
        
        if verbose and raw_output['stdout']:
            print(f"   📤 httpx RAW OUTPUT:\n{raw_output['stdout'][:2000]}")
        if verbose and raw_output['stderr']:
            print(f"   ⚠️  httpx STDERR:\n{raw_output['stderr'][:500]}")
        
        if result.returncode != 0 and not result.stdout.strip():
            if result.stderr.strip():
                print(f"⚠️  httpx stderr: {result.stderr.strip()[:200]}")
            return {'error': 'httpx failed', 'raw': raw_output}
        
        # Parse JSON output (httpx outputs one JSON object per line)
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                return {
                    'url': data.get('url', target_url),
                    'title': data.get('title', 'Unknown'),
                    'status_code': data.get('status_code'),
                    'content_length': data.get('content-length') or data.get('content_length'),
                    'technologies': data.get('tech', []),  # httpx provides tech array directly
                    'source': 'httpx',
                    'raw_output': raw_output  # FIXED: Include raw output for reports
                }
            except json.JSONDecodeError:
                return {
                    'url': target_url,
                    'title': 'Parse Error',
                    'status_code': None,
                    'content_length': None,
                    'technologies': [],
                    'source': 'httpx',
                    'raw_output': raw_output,
                    'parse_error': line[:200]
                }
        
        return {'error': 'No output parsed', 'raw': raw_output}
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  httpx timed out after {timeout}s")
        return {'error': f'Timeout after {timeout}s'}
    except Exception as e:
        print(f"⚠️  httpx execution error: {type(e).__name__}: {e}")
        return {'error': f'{type(e).__name__}: {e}'}


def run_webanalyze(target_url, timeout=30, verbose=False, apps_file=None):
    """
    Execute webanalyze CLI tool and parse JSON output.
    
    FIXED: 
    - Proper path expansion for technologies.json
    - Auto-download if missing
    - Full raw output capture for verbose mode and reports
    """
    if not BINARY_STATUS.get('webanalyze', {}).get('available'):
        return None
    
    try:
        # FIXED: Handle technologies.json path properly
        if apps_file:
            # Expand ~ to full home directory path
            apps_path = os.path.expanduser(apps_file)
            if not os.path.exists(apps_path):
                print(f"⚠️  technologies.json not found at {apps_path}, attempting auto-download...")
                # Auto-download from GitHub
                try:
                    os.makedirs(os.path.dirname(apps_path), exist_ok=True)
                    import urllib.request
                    urllib.request.urlretrieve(
                        'https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json',
                        apps_path
                    )
                    print(f"✅ Downloaded technologies.json to {apps_path}")
                except Exception as e:
                    print(f"❌ Failed to download technologies.json: {e}")
                    print("💡 Run manually: curl -L https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json -o ~/Desktop/shells/technologies.json")
                    return None
        else:
            # Use default path in script directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            apps_path = os.path.join(script_dir, 'technologies.json')
            if not os.path.exists(apps_path):
                # Try home directory fallback
                apps_path = os.path.expanduser('~/Desktop/shells/technologies.json')
        
        # Build command with proper path handling
        cmd = ['webanalyze', '-host', target_url, '-crawl', '0', '-worker', '4', '-redirect']
        
        # Only add -apps if file exists
        if os.path.exists(apps_path):
            cmd.extend(['-apps', apps_path])
        elif verbose:
            print(f"⚠️  Running webanalyze without custom apps file (using built-in fingerprints)")
        
        cmd.extend(['-output', 'json'])
        
        if verbose:
            print(f"   🔄 Executing: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        # FIXED: Capture full raw output for debugging and reports
        raw_output = {
            'stdout': result.stdout.strip()[:20000] if result.stdout else '',
            'stderr': result.stderr.strip()[:2000] if result.stderr else '',
            'returncode': result.returncode,
            'command': ' '.join(cmd),
            'apps_file': apps_path if os.path.exists(apps_path) else None
        }
        
        if verbose and raw_output['stdout']:
            print(f"   📤 webanalyze RAW OUTPUT:\n{raw_output['stdout'][:3000]}")
        if verbose and raw_output['stderr']:
            print(f"   ⚠️  webanalyze STDERR:\n{raw_output['stderr'][:500]}")
        
        if result.returncode != 0:
            if result.stderr.strip():
                print(f"⚠️  webanalyze stderr: {result.stderr.strip()[:300]}")
            return {'error': 'webanalyze failed', 'raw': raw_output}
        
        # Parse newline-delimited JSON output (webanalyze v0.3.9+ structure)
        technologies = []
        parse_errors = []
        
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                
                # webanalyze v0.3.9+ structure: {"hostname": "...", "matches": [...]}
                if isinstance(data, dict) and 'matches' in data:
                    for match in data['matches']:
                        # ✅ FIX: Extract name from 'app_name' field (not 'app')
                        app_name = match.get('app_name')
                        
                        # Fallback if app_name missing
                        if not app_name and isinstance(match.get('app'), dict):
                            app_name = match['app'].get('website', '').split('/')[-1].replace('-', ' ').title()
                        if not app_name:
                            app_name = 'Unknown'
                        
                        # ✅ FIX: Extract version from top-level 'version' field
                        version = match.get('version', '').strip() or 'Unknown'
                        
                        # ✅ FIX: Extract categories from nested 'app' dict
                        app_dict = match.get('app', {}) if isinstance(match.get('app'), dict) else {}
                        categories = app_dict.get('category_names', app_dict.get('cats', []))
                        
                        # Get confidence (default 100 if not specified)
                        confidence = match.get('confidence', 100)
                        
                        tech = {
                            'name': str(app_name).strip(),  # Ensure string
                            'version': str(version).strip(),
                            'confidence': confidence,
                            'categories': categories if isinstance(categories, list) else [],
                            'source': 'webanalyze'
                        }
                        technologies.append(tech)
                        
            except json.JSONDecodeError as e:
                parse_errors.append(f"Line parse error: {e}")
                continue
            except Exception as e:
                parse_errors.append(f"Match parse error: {type(e).__name__}: {e}")
                continue
        
        if verbose and parse_errors:
            print(f"   ⚠️  Parse warnings: {len(parse_errors)} lines skipped")
            if self.verbose:
                for err in parse_errors[:]:
                    print(f"      • {err}")
        
        return {
            'technologies': technologies,
            'url': target_url,
            'source': 'webanalyze',
            'count': len(technologies),
            'raw_output': raw_output,
            'parse_errors': parse_errors if parse_errors and verbose else None
        } if technologies else {'error': 'No technologies found', 'raw': raw_output}
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  webanalyze timed out after {timeout}s")
        return {'error': f'Timeout after {timeout}s'}
    except Exception as e:
        print(f"⚠️  webanalyze execution error: {type(e).__name__}: {e}")
        return {'error': f'{type(e).__name__}: {e}'}


def run_system_nmap_scan(target_ip, ports, timeout=180):
    """
    Execute system nmap binary via subprocess (not python-nmap library).
    
    Returns: dict with parsed scan results, or None on failure
    """
    if not BINARY_STATUS.get('nmap', {}).get('available'):
        return None
    
    try:
        ports_str = ','.join(map(str, ports))
        
        # Build nmap command: service detection + default scripts + greppable output
        cmd = [
            'nmap',
            '-sS', '-sV', '-sC',           # SYN scan, version detection, default scripts
            '-p', ports_str,                # Target ports
            '-T4',                          # Aggressive timing
            '--open',                       # Only show open ports
            '-oG', '-',                     # Greppable output to stdout
            '--min-rate', '1000',           # Speed optimization
            '--max-retries', '2',           # Reduce noise
            target_ip
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        if result.returncode not in [0, 1]:  # 0=success, 1=partial results
            if result.stderr.strip():
                print(f"⚠️  nmap stderr: {result.stderr.strip()[:300]}")
            return None
        
        # Parse greppable output (-oG -)
        return parse_nmap_grep_output(result.stdout, target_ip)
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  nmap timed out after {timeout}s")
        return None
    except Exception as e:
        print(f"⚠️  nmap execution error: {type(e).__name__}: {e}")
        return None


def parse_nmap_grep_output(grep_output, expected_host):
    """Parse nmap -oG - (greppable) output into structured dict"""
    result = {
        'host': expected_host,
        'status': 'unknown',
        'open_ports': [],
        'services': {},
        'os_detection': None,
        'script_results': {}
    }
    
    for line in grep_output.strip().split('\n'):
        if not line or line.startswith('#'):
            continue
        
        # Host line: Host: 192.168.1.1 () Status: Up
        if line.startswith('Host:'):
            parts = line.split()
            if len(parts) >= 3:
                result['host'] = parts[1]
                if 'Status:' in line:
                    result['status'] = line.split('Status:')[1].strip().split()[0]
        
        # Ports line: Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
        elif line.startswith('Ports:'):
            ports_section = line.split('Ports:')[1].strip()
            for port_entry in ports_section.split(','):
                if '/open/' in port_entry:
                    parts = port_entry.split('/')
                    if len(parts) >= 4:
                        try:
                            port_num = int(parts[0])
                            protocol = parts[2]
                            service = parts[3] if parts[3] else 'unknown'
                            version = parts[4] if len(parts) > 4 and parts[4] else None
                            
                            result['open_ports'].append(port_num)
                            result['services'][port_num] = {
                                'protocol': protocol,
                                'service': service,
                                'version': version
                            }
                        except (ValueError, IndexError):
                            continue
        
        # OS detection: OS: Linux 4.15 - 5.6
        elif line.startswith('OS:'):
            result['os_detection'] = line.split('OS:')[1].strip()
        
        # Script results: Script: vuln, Output: CVE-2021-1234 VULNERABLE
        elif line.startswith('Script:'):
            try:
                script_part = line.split('Script:')[1].strip()
                if ', Output:' in script_part:
                    script_name, output = script_part.split(', Output:', 1)
                    result['script_results'][script_name.strip()] = output.strip()
            except (ValueError, IndexError):
                pass
    
    return result


def run_sslscan(target_domain, timeout=30):
    """Execute sslscan binary and extract key certificate info"""
    if not BINARY_STATUS.get('sslscan', {}).get('available'):
        return None
    
    try:
        cmd = ['sslscan', '--no-failed', '--tlsall', target_domain]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        if result.returncode != 0:
            return None
        
        # Extract key info via regex
        cert_match = re.search(
            r'Issuer:\s*(.+?)\n.*?Subject:\s*(.+?)\n.*?Not valid before:\s*(.+?)\n.*?Not valid after:\s*(.+?)',
            result.stdout, re.DOTALL
        )
        
        protocols = re.findall(r'(\w+\s+\d+\.\d+)\s+enabled', result.stdout)
        
        return {
            'raw_output': result.stdout[:3000],  # Truncate for report
            'certificate': {
                'issuer': cert_match.group(1).strip() if cert_match else None,
                'subject': cert_match.group(2).strip() if cert_match else None,
                'not_before': cert_match.group(3).strip() if cert_match else None,
                'not_after': cert_match.group(4).strip() if cert_match else None,
            } if cert_match else None,
            'protocols': protocols
        }
        
    except subprocess.TimeoutExpired:
        print(f"⚠️  sslscan timed out after {timeout}s")
        return None
    except Exception as e:
        print(f"⚠️  sslscan execution error: {type(e).__name__}: {e}")
        return None


# ============================================================================
# MAIN OSINT CLASS
# ============================================================================

class UltraComprehensiveOSINT:
    def __init__(self, target, api_keys=None, ports=None, timeout=DEFAULT_TIMEOUT, verbose=False):
        # Initialize results FIRST (defensive coding)
        self.results = {
            'scan_metadata': {
                'tool_name': 'ULTRA-COMPREHENSIVE OSINT INTELLIGENCE GATHERER',
                'version': '3.0',
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'target': str(target).strip(),
                'scan_id': hashlib.md5(f"{target}_{datetime.now().strftime('%Y%m%d%H%M%S')}".encode()).hexdigest(),
                'verbose': verbose
            }
        }
        
        # Now safely initialize other attributes
        self.target = str(target).strip()
        self.api_keys = api_keys or {}
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout
        self.verbose = verbose
        
        # Session setup
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        })
        
        # Target resolution placeholders
        self.ip = None
        self.domain = None
        self.subdomains = []
        
    def check_dependencies(self):
        """Comprehensive dependency validation for binaries + Python packages"""
        print(f"\n{'='*80}")
        print("🔍 SYSTEM DEPENDENCY CHECK")
        print(f"{'='*80}")
        
        # External binaries status
        print(f"\n🔧 External Binaries:")
        for key, info in BINARY_STATUS.items():
            status = "✅" if info['available'] else "⚠️"
            version = info['version'] if info['available'] else 'NOT FOUND'
            print(f"   {status} {key:12s}: {version}")
        
        # Python packages
        python_pkgs = {
            'requests': 'requests',
            'beautifulsoup4': 'bs4',
            'python-whois': 'whois',
            'dnspython': 'dns',
            'shodan': 'shodan',
            'builtwith': 'builtwith',
            'pillow': 'PIL',
        }
        
        print(f"\n🐍 Python Packages:")
        for pip_name, import_name in python_pkgs.items():
            try:
                __import__(import_name)
                print(f"   ✅ {pip_name}")
            except ImportError:
                print(f"   ❌ {pip_name} (pip install {pip_name})")
        
        # Environment info
        venv = os.environ.get('VIRTUAL_ENV')
        print(f"\n📦 Virtual Environment: {venv if venv else 'Not active'}")
        print(f"🌐 Network: {'✅ Online' if self._check_internet() else '❌ Offline'}")
        print(f"💻 System: {platform_module.system()} {platform_module.release()}")
        print(f"🐍 Python: {sys.version.split()[0]}")
        print("="*80 + "\n")
    
    def _check_internet(self):
        """Quick connectivity test"""
        try:
            requests.get('https://1.1.1.1', timeout=3)
            return True
        except:
            return False
    
    def resolve_target(self):
        """Resolve target to IP + domain"""
        print(f"{'='*80}")
        print(f"🌐 TARGET RESOLUTION: {self.target}")
        print(f"{'='*80}")
        
        try:
            # Add scheme if missing
            parsed = urlparse(self.target)
            if not parsed.scheme:
                for proto in ['https', 'http']:
                    try:
                        test = f"{proto}://{self.target}"
                        r = self.session.get(test, timeout=8, verify=False)
                        if r.status_code < 500:
                            self.target = test
                            print(f"✅ Protocol: {proto.upper()} (Status: {r.status_code})")
                            break
                    except:
                        continue
            
            parsed = urlparse(self.target)
            host = parsed.netloc.split(':')[0]  # Remove port
            
            # Check if IP or domain
            try:
                socket.inet_aton(host)
                self.ip = host
                self.domain = None
                print(f"✅ Target is IP: {self.ip}")
            except socket.error:
                self.domain = host
                self.ip = socket.gethostbyname(host)
                print(f"✅ Domain resolved: {self.domain} → {self.ip}")
            
            # Geolocation lookup
            ip_info = self._get_ip_info(self.ip)
            print(f"📍 Location: {ip_info.get('city', '?')}, {ip_info.get('country', '?')}")
            print(f"🏢 ISP: {ip_info.get('isp', '?')} | ASN: {ip_info.get('asn', '?')}")
            
            self.results['target_info'] = {
                'original': self.target,
                'domain': self.domain,
                'ip': self.ip,
                'resolved_at': datetime.now().isoformat(),
                'ip_info': ip_info
            }
            print("="*80 + "\n")
            return True
            
        except Exception as e:
            print(f"❌ Resolution failed: {e}")
            return False
    
    def _get_ip_info(self, ip):
        """Get IP geolocation from free API"""
        default = {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'asn': 'Unknown'}
        
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if r.status_code == 200:
                data = r.json()
                return {
                    'country': data.get('country_name', default['country']),
                    'city': data.get('city', default['city']),
                    'isp': data.get('org', default['isp']),
                    'asn': data.get('asn', default['asn']),
                    'loc': f"{data.get('latitude')},{data.get('longitude')}"
                }
        except:
            pass
        
        return default
    
    # -------------------------------------------------------------------------
    # MODULE: WHOIS
    # -------------------------------------------------------------------------
    
    def get_whois_info(self):
        """Gather WHOIS registration data"""
        print(f"{'='*80}\n📋 WHOIS INFORMATION\n{'='*80}")
        
        if not self.domain:
            print("⏭️  Skipped (target is IP)")
            return
        
        try:
            w = whois.whois(self.domain)
            
            def _norm_date(d):
                if isinstance(d, list): return d[0] if d else None
                return d
            
            creation = _norm_date(w.creation_date)
            expiry = _norm_date(w.expiration_date)
            
            whois_data = {
                'registrar': str(w.registrar) if w.registrar else None,
                'creation_date': str(creation) if creation else None,
                'expiration_date': str(expiry) if expiry else None,
                'name_servers': [str(ns).lower() for ns in (w.name_servers or [])],
                'status': [str(s) for s in (w.status or [])],
                'emails': list(set([str(e).lower() for e in (w.emails or [])])),
                'organization': str(w.org) if w.org else None,
                'country': str(w.country) if w.country else None,
            }
            
            if creation and expiry:
                try:
                    if isinstance(creation, str):
                        creation = datetime.strptime(creation.split()[0], '%Y-%m-%d')
                    if isinstance(expiry, str):
                        expiry = datetime.strptime(expiry.split()[0], '%Y-%m-%d')
                    whois_data['age_days'] = (datetime.now() - creation).days
                    whois_data['expires_in_days'] = (expiry - datetime.now()).days
                except:
                    pass
            
            print(f"🏢 Registrar: {whois_data['registrar'] or 'Unknown'}")
            print(f"📅 Created: {whois_data['creation_date'] or 'Unknown'}")
            print(f"⏰ Expires: {whois_data['expiration_date'] or 'Unknown'}")
            if whois_data.get('expires_in_days') is not None:
                status = "⚠️ EXPIRING SOON" if whois_data['expires_in_days'] < 30 else "✅ Healthy"
                print(f"   └─ {whois_data['expires_in_days']} days remaining ({status})")
            print(f"🔧 Nameservers: {len(whois_data['name_servers'])} configured")
            print(f"📧 Contact emails: {len(whois_data['emails'])} found")
            
            self.results['whois'] = whois_data
            print("✅ WHOIS collected\n" + "="*80 + "\n")
            
        except Exception as e:
            print(f"❌ WHOIS failed: {e}")
            self.results['whois'] = {'error': str(e)}
    
    # -------------------------------------------------------------------------
    # MODULE: DNS ANALYSIS
    # -------------------------------------------------------------------------
    
    def comprehensive_dns_scan(self):
        """Comprehensive DNS enumeration"""
        print(f"{'='*80}\n🔍 DNS ANALYSIS\n{'='*80}")
        
        if not self.domain:
            print("⏭️  Skipped (target is IP)")
            return
        
        dns_results = {}
        
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                records = [str(r).rstrip('.') for r in answers]
                dns_results[rtype] = records
                print(f"✅ {rtype}: {len(records)} record(s)")
                
                if rtype == 'TXT':
                    for rec in records:
                        if 'v=spf1' in rec.lower():
                            print(f"   └─ 📧 SPF: {rec[:80]}...")
                        elif 'v=dmarc1' in rec.lower():
                            print(f"   └─ 🛡️  DMARC: {rec[:80]}...")
                elif rtype == 'MX':
                    for rec in records:
                        print(f"   └─ ✉️  {rec}")
                        
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dns_results[rtype] = []
            except Exception as e:
                print(f"⚠️  {rtype} query failed: {e}")
                dns_results[rtype] = []
        
        # Reverse DNS
        try:
            rev = dns.reversename.from_address(self.ip)
            ptr = str(dns.resolver.resolve(rev, 'PTR')[0]).rstrip('.')
            dns_results['PTR'] = ptr
            print(f"✅ Reverse DNS: {ptr}")
        except:
            pass
        
        # Subdomain enumeration
        subdomains_to_check = [
            'www', 'mail', 'webmail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'mobile', 'm', 'blog', 'shop', 'cdn', 'static', 'app', 'portal',
            'secure', 'vpn', 'remote', 'owa', 'cpanel', 'whm', 'autodiscover'
        ]
        
        found_subs = []
        print(f"\n🔎 Checking {len(subdomains_to_check)} common subdomains...")
        
        for sub in subdomains_to_check:
            fqdn = f"{sub}.{self.domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A', lifetime=2)
                for ans in answers:
                    ip_found = str(ans)
                    print(f"   ✅ {fqdn} → {ip_found}")
                    found_subs.append({'subdomain': sub, 'fqdn': fqdn, 'ip': ip_found})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
            except Exception:
                continue
        
        dns_results['subdomains_found'] = found_subs
        self.subdomains = [s['fqdn'] for s in found_subs]
        print(f"📊 Found {len(found_subs)} active subdomains")
        
        self.results['dns'] = dns_results
        print("✅ DNS analysis complete\n" + "="*80 + "\n")
    
    # -------------------------------------------------------------------------
    # MODULE: NMAP PORT SCAN (System Binary via Subprocess)
    # -------------------------------------------------------------------------
    
    def comprehensive_nmap_scan(self):
        """Port scanning using SYSTEM nmap binary via subprocess"""
        print(f"{'='*80}\n🔍 NMAP PORT SCAN (System Binary)\n{'='*80}")
        
        if not BINARY_STATUS.get('nmap', {}).get('available'):
            print("❌ nmap binary not available - skipping port scan")
            self.results['nmap'] = {'error': 'nmap binary not found in PATH'}
            return
        
        try:
            print(f"🎯 Scanning {self.ip} ports: {','.join(map(str, self.ports))}")
            
            nmap_result = run_system_nmap_scan(self.ip, self.ports, timeout=self.timeout * 6)
            
            if not nmap_result:
                print("⚠️  nmap scan returned no results")
                self.results['nmap'] = {'error': 'Scan failed or no open ports'}
                return
            
            print(f"\n🚪 OPEN PORTS:")
            for port in sorted(nmap_result.get('open_ports', [])):
                svc_info = nmap_result.get('services', {}).get(port, {})
                svc = svc_info.get('service', 'unknown')
                ver = svc_info.get('version', '')
                print(f"   ✅ {port}/{svc_info.get('protocol', 'tcp')}: {svc} {ver}".strip())
            
            if nmap_result.get('os_detection'):
                print(f"\n🖥️  Likely OS: {nmap_result['os_detection']}")
            
            if nmap_result.get('script_results'):
                print(f"\n📜 NSE Script Results:")
                for script, output in nmap_result['script_results'].items():
                    clean = output.strip().replace('\n', ' ')
                    print(f"   • {script}: {clean[:120]}...")
            
            self.results['nmap'] = {
                'host': nmap_result.get('host'),
                'status': nmap_result.get('status'),
                'open_ports': nmap_result.get('open_ports', []),
                'services': nmap_result.get('services', {}),
                'os_detection': nmap_result.get('os_detection'),
                'script_results': nmap_result.get('script_results', {}),
                'total_scanned': len(self.ports),
            }
            
            print(f"\n📊 Summary: {len(nmap_result.get('open_ports', []))}/{len(self.ports)} ports open")
            print("✅ Nmap scan complete\n" + "="*80 + "\n")
            
        except Exception as e:
            print(f"❌ Nmap scan failed: {e}")
            self.results['nmap'] = {'error': str(e)}
    
    # -------------------------------------------------------------------------
    # MODULE: SSL/TLS ANALYSIS
    # -------------------------------------------------------------------------
    
    def detailed_ssl_tls_analysis(self):
        """SSL/TLS certificate and configuration analysis"""
        print(f"{'='*80}\n🔒 SSL/TLS ANALYSIS\n{'='*80}")
        
        if not self.domain:
            print("⏭️  Skipped (target is IP)")
            return
        
        ssl_data = {'enabled': False}
        
        # Method 1: sslscan binary
        if BINARY_STATUS.get('sslscan', {}).get('available'):
            try:
                print("🔍 Running sslscan...")
                scan_result = run_sslscan(self.domain, timeout=self.timeout)
                
                if scan_result:
                    cert = scan_result.get('certificate')
                    if cert:
                        print(f"📋 Certificate:")
                        print(f"   • Subject: {cert.get('subject', 'Unknown')[:60]}")
                        print(f"   • Issuer: {cert.get('issuer', 'Unknown')[:60]}")
                        print(f"   • Valid: {cert.get('not_before', '?')} → {cert.get('not_after', '?')}")
                    
                    protocols = scan_result.get('protocols', [])
                    if protocols:
                        print(f"📡 Protocols: {', '.join(protocols)}")
                    
                    ssl_data['sslscan_available'] = True
                    ssl_data['protocols'] = protocols
                    ssl_data['certificate'] = cert
                    
            except Exception as e:
                print(f"⚠️  sslscan failed: {e}")
        
        # Method 2: Python SSL socket (fallback)
        try:
            print("\n🔍 Python SSL handshake...")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    ssl_data.update({
                        'enabled': True,
                        'version': ssock.version(),
                        'cipher': cipher[0] if cipher else None,
                        'cipher_bits': cipher[2] if cipher else None,
                    })
                    
                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        ssl_data['certificate'] = {
                            'subject': subject.get('commonName', subject.get('CN', 'Unknown')),
                            'issuer': issuer.get('commonName', issuer.get('CN', 'Unknown')),
                            'valid_from': cert.get('notBefore'),
                            'valid_to': cert.get('notAfter'),
                            'sans': [name[1] for name in cert.get('subjectAltName', []) if name[0] == 'DNS']
                        }
                        
                        print(f"✅ TLS {ssl_data['version']} | Cipher: {ssl_data['cipher']}")
                        print(f"📋 Cert: {ssl_data['certificate']['subject']}")
                        
                        if cert.get('notAfter'):
                            try:
                                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                                days_left = (expiry - datetime.now()).days
                                print(f"⏰ Expires in {days_left} days" + (" ⚠️ SOON!" if days_left < 30 else ""))
                            except:
                                pass
                    
                    self.results['ssl_tls'] = ssl_data
                    print("✅ SSL/TLS analysis complete")
                    
        except Exception as e:
            print(f"❌ SSL analysis failed: {e}")
            self.results['ssl_tls'] = {'enabled': False, 'error': str(e)}
        
        print("="*80 + "\n")
    
    # -------------------------------------------------------------------------
    # MODULE: TECHNOLOGY DETECTION (httpx + webanalyze ONLY)
    # -------------------------------------------------------------------------
    
    def advanced_technology_detection(self):
        """Multi-source technology fingerprinting using httpx + webanalyze"""
        print(f"{'='*80}\n🚀 TECHNOLOGY DETECTION (httpx + webanalyze)\n{'='*80}")
        
        # Initialize local variables (properly indented inside method)
        all_technologies = {}
        raw_outputs = {'httpx': None, 'webanalyze': None}
        httpx_result = None
        
        # ------------------------------------------------------------
        # Source 1: httpx CLI
        # ------------------------------------------------------------
        if BINARY_STATUS.get('httpx', {}).get('available'):
            try:
                print("🔍 Method 1: httpx CLI")
                httpx_result = run_httpx_scan(
                    self.target, 
                    timeout=self.timeout,
                    verbose=self.verbose
                )

                if httpx_result:
                    # Store raw output for reports
                    raw_outputs['httpx'] = httpx_result.get('raw_output')

                    if httpx_result.get('error'):
                        print(f"   ⚠️  httpx returned an error: {httpx_result['error']}")
                    else:
                        print(f"   ✅ httpx: Status={httpx_result.get('status_code')}, "
                              f"Title={httpx_result.get('title', 'Unknown')[:50]}")

                        # Parse httpx tech list if -tech-detect succeeded
                        httpx_techs = httpx_result.get('technologies', [])
                        if httpx_techs:
                            print(f"   ℹ️  httpx detected {len(httpx_techs)} tech(s) directly")
                            for tech in httpx_techs[:10]:
                                tech_name = tech if isinstance(tech, str) else tech.get('name', 'Unknown')
                                print(f"      • {tech_name}")

            except Exception as e:
                print(f"   ⚠️  httpx integration failed: {e}")

        # ------------------------------------------------------------
        # Source 2: webanalyze CLI
        # ------------------------------------------------------------
        if BINARY_STATUS.get('webanalyze', {}).get('available'):
            try:
                print("🔍 Method 2: webanalyze CLI")
                webanalyze_result = run_webanalyze(
                    self.target, 
                    timeout=self.timeout,
                    verbose=self.verbose,
                    apps_file=os.path.expanduser('~/Desktop/shells/technologies.json')
                )

                if webanalyze_result:
                    raw_outputs['webanalyze'] = webanalyze_result.get('raw_output')

                    if webanalyze_result.get('error'):
                        print(f"   ⚠️  webanalyze error: {webanalyze_result['error']}")
                    elif 'technologies' in webanalyze_result:
                        tech_list = webanalyze_result['technologies']
                        for tech in tech_list:
                            cats = tech.get('categories', ['Other'])
                            cat = cats[0] if cats else 'Other'
                            all_technologies.setdefault(cat, [])

                            # Avoid duplicates
                            if not any(t['name'].lower() == tech['name'].lower()
                                       for t in all_technologies[cat]):
                                all_technologies[cat].append({
                                    'name': tech['name'],
                                    'version': tech.get('version', 'Unknown'),
                                    'confidence': tech.get('confidence', 100),
                                    'source': 'webanalyze'
                                })
                        print(f"   ✅ webanalyze: {len(tech_list)} technologies detected")
                    else:
                        print("   ⚠️  webanalyze returned no 'technologies' key")
                else:
                    print("   ⚠️  webanalyze: no result")

            except Exception as e:
                print(f"   ⚠️  webanalyze integration failed: {e}")

        # ------------------------------------------------------------
        # Source 3: BuiltWith API (optional)
        # ------------------------------------------------------------
        if self.api_keys.get('builtwith'):
            try:
                print("🔍 Method 3: BuiltWith API")
                bw = builtwith.parse(self.target, key=self.api_keys['builtwith'])
                for category, items in bw.items():
                    all_technologies.setdefault(category, [])
                    for item in items:
                        all_technologies[category].append({
                            'name': item.split(' v')[0].strip() if ' v' in item else item,
                            'version': item.split(' v')[1].strip() if ' v' in item else 'Unknown',
                            'confidence': 90,
                            'source': 'BuiltWith'
                        })
                print(f"   ✅ BuiltWith: added technologies")
            except Exception as e:
                print(f"   ⚠️  BuiltWith failed: {e}")

        # ------------------------------------------------------------
        # Vulnerability correlation
        # ------------------------------------------------------------
        vuln_db = {
            'wordpress': {'4.7-5.8': [{'id': 'CVE-2021-29447', 'severity': 'high',
                                       'summary': 'XXE in media library'}]},
            'jquery': {'1.2-3.4': [{'id': 'CVE-2020-11022', 'severity': 'medium',
                                    'summary': 'XSS in htmlPrefilter'}]},
            'apache': {'2.4.0-2.4.48': [{'id': 'CVE-2021-41773', 'severity': 'critical',
                                         'summary': 'Path traversal'}]},
            'nginx': {'1.0-1.20': [{'id': 'CVE-2021-23017', 'severity': 'high',
                                    'summary': 'DNS resolver vulnerability'}]}
        }

        vulnerabilities = {}
        for cat, techs in all_technologies.items():
            for tech in techs:
                name = tech['name'].lower()
                version = tech.get('version', '').lower()
                for vuln_name, version_ranges in vuln_db.items():
                    if vuln_name in name:
                        for ver_range, vulns in version_ranges.items():
                            try:
                                min_ver, max_ver = ver_range.split('-')
                                if min_ver <= version <= max_ver:
                                    key = f"{name}-{version}"
                                    vulnerabilities[key] = vulns
                                    break
                            except:
                                continue

        # ------------------------------------------------------------
        # Store everything in self.results (properly indented)
        # ------------------------------------------------------------
        self.results['technologies'] = {
            'by_category': all_technologies,
            'vulnerabilities': vulnerabilities,
            'sources_used': [s for s in ['httpx', 'webanalyze', 'BuiltWith']
                             if any(t['source'] == s for cat in all_technologies.values() for t in cat)],
            'httpx_basic': {
                'title': httpx_result.get('title') if httpx_result and not httpx_result.get('error') else None,
                'status_code': httpx_result.get('status_code') if httpx_result and not httpx_result.get('error') else None,
                'content_length': httpx_result.get('content_length') if httpx_result and not httpx_result.get('error') else None
            } if httpx_result and not httpx_result.get('error') else None
        }

        # Attach raw tool outputs to global raw store (used for JSON export)
        self.results.setdefault('raw_tool_outputs', {})
        self.results['raw_tool_outputs'].update({k: v for k, v in raw_outputs.items() if v})

        # ------------------------------------------------------------
        # Print summary
        # ------------------------------------------------------------
        total = sum(len(v) for v in all_technologies.values())
        vuln_count = sum(len(v) for v in vulnerabilities.values())
        print(f"\n📊 Summary: {total} technologies detected, {vuln_count} potential vulnerabilities")

        for cat, techs in sorted(all_technologies.items()):
            print(f"\n📁 {cat.upper()}:")
            for t in techs[:5]:
                ver = f" v{t['version']}" if t['version'] != 'Unknown' else ""
                print(f"   • {t['name']}{ver} ({t['confidence']}% | {t['source']})")
            if len(techs) > 5:
                print(f"   └─ ... and {len(techs)-5} more")

        print("\n✅ Technology detection complete\n" + "="*80 + "\n")
            
    # -------------------------------------------------------------------------
    # MODULE: WEB CONTENT ANALYSIS
    # -------------------------------------------------------------------------
    
    def comprehensive_web_content_analysis(self):
        """Extract emails, links, headers, metadata"""
        print(f"{'='*80}\n📝 WEB CONTENT ANALYSIS\n{'='*80}")
        
        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            content = {}
            
            # Metadata
            meta = {}
            for tag in soup.find_all('meta'):
                name = tag.get('name') or tag.get('property') or tag.get('http-equiv')
                if name and tag.get('content'):
                    meta[name.lower()] = tag['content'].strip()
            content['meta_tags'] = meta
            
            # Title & description
            title = soup.title.string.strip() if soup.title else 'No title'
            content['title'] = title
            print(f"🏷️  Title: {title[:80]}{'...' if len(title) > 80 else ''}")
            
            # Links analysis
            links = soup.find_all('a', href=True)
            internal = [l['href'] for l in links if self.domain and self.domain in l['href']]
            external = [l['href'] for l in links if l['href'].startswith('http') and self.domain not in l['href']]
            content['links'] = {'total': len(links), 'internal': len(internal), 'external': len(external)}
            print(f"🔗 Links: {len(links)} total ({len(internal)} internal, {len(external)} external)")
            
            # Email extraction
            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text))
            content['emails'] = list(emails)
            if emails:
                print(f"📧 Emails found: {len(emails)}")
                for e in list(emails)[:5]:
                    print(f"   └─ {e}")
            
            # Security headers
            sec_headers = [
                'strict-transport-security', 'content-security-policy',
                'x-content-type-options', 'x-frame-options', 'x-xss-protection',
                'referrer-policy', 'permissions-policy'
            ]
            present = [h for h in sec_headers if h in response.headers]
            missing = [h for h in sec_headers if h not in response.headers]
            content['security_headers'] = {'present': present, 'missing': missing}
            print(f"🛡️  Security headers: {len(present)}/{len(sec_headers)} present")
            if missing:
                print(f"   ❌ Missing: {', '.join(missing[:3])}{'...' if len(missing) > 3 else ''}")
            
            self.results['web_content'] = content
            print("✅ Web content analysis complete\n" + "="*80 + "\n")
            
        except Exception as e:
            print(f"❌ Web analysis failed: {e}")
            self.results['web_content'] = {'error': str(e)}
    
    # -------------------------------------------------------------------------
    # MODULE: SHODAN INTEGRATION
    # -------------------------------------------------------------------------
    
    def shodan_analysis(self):
        """Query Shodan for host intelligence"""
        print(f"{'='*80}\n🔍 SHODAN INTELLIGENCE\n{'='*80}")
        
        if not self.api_keys.get('shodan'):
            print("⏭️  Skipped (no Shodan API key)")
            print("💡 Add key: --shodan-api YOUR_KEY")
            return
        
        try:
            api = Shodan(self.api_keys['shodan'])
            print(f"🎯 Querying Shodan for: {self.ip}")
            
            host = api.host(self.ip)
            
            print(f"\n📊 Shodan Summary:")
            print(f"   • Hostnames: {', '.join(host.get('hostnames', ['None']))}")
            print(f"   • Location: {host.get('country_name', '?')}, {host.get('city', '?')}")
            print(f"   • ISP: {host.get('isp', '?')} | Org: {host.get('org', '?')}")
            print(f"   • Ports: {len(host.get('ports', []))} open")
            print(f"   • Vulns: {len(host.get('vulns', {}))} known")
            
            if host.get('ports'):
                print(f"\n🚪 Open Ports:")
                for port in host['ports'][:10]:
                    print(f"   • {port}")
                if len(host['ports']) > 10:
                    print(f"   └─ ... and {len(host['ports'])-10} more")
            
            if host.get('vulns'):
                print(f"\n🚨 Known Vulnerabilities:")
                for vid, vdata in list(host['vulns'].items())[:5]:
                    cvss = vdata.get('cvss', 'N/A')
                    summary = vdata.get('summary', 'No description')[:60]
                    print(f"   • {vid}: {summary}... (CVSS: {cvss})")
            
            self.results['shodan'] = {
                'ip': host.get('ip_str'),
                'hostnames': host.get('hostnames', []),
                'country': host.get('country_name'),
                'ports': host.get('ports', []),
                'vulns': list(host.get('vulns', {}).keys()),
                'last_update': host.get('last_update')
            }
            
            print("\n✅ Shodan analysis complete\n" + "="*80 + "\n")
            
        except APIError as e:
            print(f"❌ Shodan API error: {e}")
            self.results['shodan'] = {'error': str(e)}
        except Exception as e:
            print(f"❌ Shodan failed: {e}")
            self.results['shodan'] = {'error': str(e)}
    
    # -------------------------------------------------------------------------
    # REPORT GENERATION
    # -------------------------------------------------------------------------
    
    def generate_comprehensive_report(self):
        """Generate executive summary report"""
        print(f"{'='*80}\n📈 GENERATING REPORT\n{'='*80}")
        
        lines = []
        lines.append("="*80)
        lines.append("ULTRA-COMPREHENSIVE OSINT INTELLIGENCE REPORT v3.0")
        lines.append(f"Target: {self.target}")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Scan ID: {self.results['scan_metadata']['scan_id']}")
        lines.append("="*80 + "\n")
        
        # Executive Summary
        lines.append("🎯 EXECUTIVE SUMMARY")
        lines.append("-"*40)
        
        if 'target_info' in self.results:
            ti = self.results['target_info']
            lines.append(f"• Target: {ti.get('original')}")
            lines.append(f"• IP: {ti.get('ip')}")
            if ti.get('ip_info'):
                loc = ti['ip_info']
                lines.append(f"• Location: {loc.get('city', '?')}, {loc.get('country', '?')}")
        
        # Security score calculation
        score = 100
        issues = []
        
        ssl = self.results.get('ssl_tls', {})
        if not ssl.get('enabled'):
            score -= 25
            issues.append("No SSL/TLS")
        elif ssl.get('version') in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            score -= 15
            issues.append(f"Outdated TLS: {ssl.get('version')}")
        
        web = self.results.get('web_content', {})
        if 'security_headers' in web:
            missing = web['security_headers'].get('missing', [])
            if len(missing) > 3:
                score -= 10
                issues.append(f"{len(missing)} missing security headers")
        
        critical_vulns = 0
        techs = self.results.get('technologies', {})
        vulns = techs.get('vulnerabilities', {})
        for vlist in vulns.values():
            for v in vlist:
                if v.get('severity', '').lower() in ['critical', 'high']:
                    critical_vulns += 1
        
        if critical_vulns > 0:
            score -= critical_vulns * 12
            issues.append(f"{critical_vulns} critical/high vulns in tech stack")
        
        score = max(0, min(100, score))
        rating = "Excellent" if score >= 80 else "Good" if score >= 60 else "Fair" if score >= 40 else "Poor"
        
        lines.append(f"\n🛡️  Security Score: {score}/100 ({rating})")
        if issues:
            lines.append("⚠️  Issues Found:")
            for issue in issues:
                lines.append(f"   • {issue}")
        
        if 'technologies' in self.results:
            tech_data = self.results['technologies']
            total_tech = sum(len(v) for v in tech_data.get('by_category', {}).values())
            lines.append(f"\n🚀 Technologies: {total_tech} detected")
            lines.append(f"   Sources: {', '.join(tech_data.get('sources_used', []))}")
        
        if 'web_content' in self.results and 'emails' in self.results['web_content']:
            emails = self.results['web_content']['emails']
            if emails:
                lines.append(f"\n📧 Contact Intel: {len(emails)} email(s) discovered")
        
        # Recommendations
        lines.append("\n" + "="*80)
        lines.append("🚀 TOP RECOMMENDATIONS")
        lines.append("-"*80)
        recs = [
            f"1. Patch {critical_vulns} critical/high vulnerabilities immediately" if critical_vulns > 0 else "1. Keep all software updated",
            "2. Implement missing security headers (HSTS, CSP, X-Content-Type-Options)",
            "3. Configure SPF/DKIM/DMARC for email authentication",
            "4. Enable WAF and rate limiting on public endpoints",
            "5. Conduct regular vulnerability scans and penetration tests"
        ]
        for rec in recs:
            lines.append(f"• {rec}")
        
        lines.append("\n" + "="*80)
        lines.append(f"Report generated by ULTRA-COMPREHENSIVE OSINT v3.0")
        lines.append(f"System: {platform_module.system()} | Python: {sys.version.split()[0]}")
        lines.append("="*80)
        
        report = "\n".join(lines)
        self.results['report'] = report
        print("✅ Report generated\n" + "="*80 + "\n")
        return report
    
    # -------------------------------------------------------------------------
    # MAIN EXECUTION
    # -------------------------------------------------------------------------
    
    def perform_full_intelligence_gathering(self):
        """Run all modules in sequence"""
        print(f"""
{'='*80}
🎯 ULTRA-COMPREHENSIVE OSINT INTELLIGENCE GATHERER v3.0
{'='*80}
Target: {self.target}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
System: {platform_module.system()} {platform_module.release()}
Python: {sys.version.split()[0]}
External Tools: {[k for k,v in BINARY_STATUS.items() if v['available']]}
{'='*80}
""")
        
        self.check_dependencies()
        
        if not self.resolve_target():
            print("❌ Target resolution failed")
            return False, None
        
        modules = [
            ("WHOIS", self.get_whois_info),
            ("DNS Analysis", self.comprehensive_dns_scan),
            ("Nmap Scan", self.comprehensive_nmap_scan),
            ("SSL/TLS", self.detailed_ssl_tls_analysis),
            ("Technology Detection", self.advanced_technology_detection),
            ("Web Content", self.comprehensive_web_content_analysis),
            ("Shodan", self.shodan_analysis)
        ]
        
        start = time.time()
        
        for name, func in modules:
            print(f"\n▶️  Running: {name}")
            try:
                t0 = time.time()
                func()
                t1 = time.time()
                print(f"✅ {name} completed in {t1-t0:.2f}s")
            except Exception as e:
                print(f"❌ {name} failed: {e}")
                self.results[f"{name}_error"] = str(e)
            time.sleep(0.5)
        
        total_time = time.time() - start
        self.results['scan_metadata']['duration_seconds'] = round(total_time, 2)
        
        report = self.generate_comprehensive_report()
        
        print(f"\n{'='*80}")
        print("✅ SCAN COMPLETE")
        print(f"{'='*80}")
        print(f"⏱️  Duration: {total_time:.2f} seconds")
        print(f"📊 Data points collected: {len(self.results)}")
        if 'technologies' in self.results:
            tech_count = sum(len(v) for v in self.results['technologies'].get('by_category', {}).values())
            print(f"🚀 Technologies: {tech_count}")
        if 'web_content' in self.results and 'emails' in self.results['web_content']:
            print(f"📧 Emails: {len(self.results['web_content']['emails'])}")
        print("="*80)
        
        return True, report


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='ULTRA-COMPREHENSIVE OSINT INTELLIGENCE GATHERER v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXTERNAL BINARIES REQUIRED (install outside Python venv):
  • nmap: apt install nmap | brew install nmap
  • httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  • webanalyze: go install github.com/rverton/webanalyze/cmd/webanalyze@latest
  • sslscan: apt install sslscan | brew install sslscan

Examples:
  %(prog)s example.com
  %(prog)s https://target.com -o report.txt -j data.json
  %(prog)s 192.168.1.1 --shodan-api YOUR_KEY --ports 22,80,443,8080
        """
    )
    
    parser.add_argument('target', help='Target URL or IP address')
    parser.add_argument('-o', '--output', help='Save text report to file')
    parser.add_argument('-j', '--json', help='Save raw JSON data to file')
    parser.add_argument('--shodan-api', help='Shodan API key')
    parser.add_argument('--builtwith-key', help='BuiltWith API key')
    parser.add_argument('--ports', help='Comma-separated list of ports to scan (default: common ports)')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='Request timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output: show full httpx/webanalyze raw responses')
    
    args = parser.parse_args()
    
    # Prepare API keys
    api_keys = {}
    if args.shodan_api:
        api_keys['shodan'] = args.shodan_api
    if args.builtwith_key:
        api_keys['builtwith'] = args.builtwith_key
    
    # Parse ports
    ports = DEFAULT_PORTS
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]
        except ValueError:
            print(f"⚠️  Invalid port list, using defaults: {DEFAULT_PORTS}")
    
    # Run scanner
    scanner = UltraComprehensiveOSINT(args.target, api_keys, ports, args.timeout, args.verbose)
    
    success, report = scanner.perform_full_intelligence_gathering()
    
    if success and report:
        # Save text report if requested
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"\n✅ Report saved: {args.output}")
            except Exception as e:
                print(f"❌ Failed to save report: {e}")
        
        # Save JSON data if requested
        if args.json:
            try:
                # Ensure raw tool outputs are in results
                if 'raw_tool_outputs' not in scanner.results:
                    scanner.results['raw_tool_outputs'] = {}
                
                with open(args.json, 'w', encoding='utf-8') as f:
                    json.dump(scanner.results, f, indent=2, default=str)
                print(f"✅ JSON data saved: {args.json}")
                print(f"   📦 Includes raw httpx/webanalyze output: {'raw_tool_outputs' in scanner.results}")
            except Exception as e:
                print(f"❌ Failed to save JSON: {e}")
        
        # Print report to terminal if no file output requested
        if not args.output:
            print("\n" + report)
        
        return 0
    else:
        print("❌ Scan failed. Check target and connectivity.")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⏹️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {type(e).__name__}: {e}")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
