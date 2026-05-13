"""
APIX v3 - Core Logic
All tool execution classes with QThread support for non-blocking UI
"""

import subprocess
import requests
import socket
import json
import re
import time
import urllib.parse
import webbrowser
from pathlib import Path
from PyQt5.QtCore import QThread, pyqtSignal

# ============ WORDLISTS ============
API_ENDPOINTS = [
    # Auth
    "/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/register",
    "/api/v1/auth/refresh", "/api/v1/auth/token", "/api/v1/auth/verify",
    "/api/v2/auth/login", "/api/v2/auth/token",
    "/auth/login", "/auth/token", "/auth/register", "/auth/refresh",
    # Users
    "/api/v1/users", "/api/v1/user", "/api/v1/users/me", "/api/v1/profile",
    "/api/v2/users", "/api/v2/user", "/api/users", "/users", "/user", "/me",
    # Admin
    "/api/v1/admin", "/api/v1/admin/users", "/api/v1/admin/config",
    "/api/v1/admin/dashboard", "/api/v1/admin/settings", "/api/v1/admin/logs",
    "/api/v2/admin", "/admin", "/admin/users", "/admin/config",
    # Config & Debug
    "/api/v1/config", "/api/v1/settings", "/api/v1/status", "/api/v1/health",
    "/api/v1/version", "/api/v1/debug", "/api/v1/test", "/api/v1/info",
    "/config", "/settings", "/status", "/health", "/debug", "/info", "/ping",
    # Files
    "/api/v1/upload", "/api/v1/files", "/api/v1/media", "/api/v1/documents",
    "/upload", "/files", "/media", "/.env", "/.git/config",
    # Sensitive
    "/api/v1/keys", "/api/v1/tokens", "/api/v1/secrets", "/api/v1/backup",
    "/api/v1/logs", "/api/v1/audit", "/api/v1/metrics", "/api/v1/stats",
    # Docs
    "/swagger.json", "/swagger-ui", "/api-docs", "/openapi.json",
    "/openapi.yaml", "/docs", "/graphql", "/graphiql", "/gql",
    # Version variants
    "/api/v1/", "/api/v2/", "/api/v3/", "/v1/", "/v2/", "/v3/",
    # Extensions
    "/config.json", "/settings.json", "/data.json", "/backup.json",
    "/admin.php", "/login.php", "/config.php", "/phpinfo.php",
    "/robots.txt", "/sitemap.xml", "/.env.local", "/.env.backup",
    # CRUD
    "/api/v1/products", "/api/v1/orders", "/api/v1/payments",
    "/api/v1/roles", "/api/v1/permissions", "/api/v1/groups",
    "/api/v1/notifications", "/api/v1/messages", "/api/v1/webhooks",
]

HIDDEN_PARAMS = [
    "debug", "admin", "test", "dev", "id", "user", "username", "password",
    "token", "key", "secret", "config", "setting", "role", "privilege",
    "access", "cmd", "exec", "command", "query", "search", "filter",
    "redirect", "url", "path", "file", "dir", "page", "limit", "offset",
    "format", "callback", "action", "mode", "type", "version", "lang",
    "api_key", "api_token", "auth", "authorization", "bearer",
    "superuser", "root", "god", "master", "owner", "internal",
]

GOOGLE_DORKS = [
    ('Credential Files', [
        'site:{domain} ext:env',
        'site:{domain} ext:php inurl:config',
        'site:{domain} "web.config"',
        'site:{domain} ext:py inurl:settings',
        'site:{domain} ".git/config"',
    ]),
    ('Backups & Dumps', [
        'site:{domain} ext:sql',
        'site:{domain} ext:bak',
        'site:{domain} ext:old',
        'site:{domain} ext:db',
        'site:{domain} "backup.zip"',
    ]),
    ('Source Code Exposure', [
        'site:{domain} ext:log',
        'site:{domain} "phpinfo.php"',
        'site:{domain} "error_log"',
        'site:{domain} ext:txt inurl:password',
        'site:{domain} inurl:admin ext:php',
    ]),
    ('API Keys & Secrets', [
        'site:{domain} "api_key"',
        'site:{domain} "apikey"',
        'site:{domain} "secret_key"',
        'site:{domain} "access_token"',
    ]),
]

SEVERITY_COLORS = {
    "critical": "#ff0044",
    "high": "#ff6600",
    "medium": "#ffaa00",
    "low": "#44aaff",
    "info": "#aaaaaa",
}


# ============ BASE THREAD ============
class BaseThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)

    def log(self, msg, level="INFO"):
        colors = {"INFO": "#00ff88", "WARN": "#ffaa00", "ERROR": "#ff3366",
                  "FOUND": "#ffffff", "VULN": "#ff0044"}
        color = colors.get(level, "#00ff88")
        self.log_signal.emit(f'<span style="color:{color}">[{level}] {msg}</span>')


# ============ RECON: SUBDOMAINS ============
class SubdomainScanner(BaseThread):
    subdomain_found = pyqtSignal(str)

    def __init__(self, domain, use_subfinder=True, use_shuffledns=False,
                 wordlist=None, resolvers=None):
        super().__init__()
        self.domain = domain
        self.use_subfinder = use_subfinder
        self.use_shuffledns = use_shuffledns
        self.wordlist = wordlist
        self.resolvers = resolvers

    def run(self):
        try:
            self.log(f"Starting subdomain scan for {self.domain}")

            if self.use_subfinder:
                self._run_subfinder()

            if self.use_shuffledns and self.wordlist:
                self._run_shuffledns_pipeline()

            self.log("Subdomain scan complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))

    def _run_subfinder(self):
        self.log("Running Subfinder...")
        try:
            proc = subprocess.Popen(
                ["subfinder", "-d", self.domain, "-silent"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            for line in proc.stdout:
                sub = line.strip()
                if sub:
                    self.log(f"[Subfinder] Found: {sub}", "FOUND")
                    self.subdomain_found.emit(sub)
            proc.wait()
        except FileNotFoundError:
            self.log("subfinder not found", "WARN")

    def _run_shuffledns_pipeline(self):
        self.log("Running ShuffleDNS + Alterx + DNSx + Naabu + httpx pipeline...")
        try:
            resolvers = self.resolvers or "/usr/share/seclists/Miscellaneous/dns-resolvers.txt"
            wordlist = self.wordlist or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

            pipeline = (
                f"shuffledns -d {self.domain} -w {wordlist} -r {resolvers} -mode bruteforce -silent"
                f" | alterx -silent"
                f" | dnsx -silent"
                f" | naabu -top-ports 100 -exclude-ports 9999 -silent"
                f" | httpx-toolkit -title -sc -cl -location -fr -silent"
            )

            self.log(f"Pipeline: {pipeline}", "INFO")

            proc = subprocess.Popen(
                ["bash", "-c", pipeline],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            for line in proc.stdout:
                line = line.strip()
                if line:
                    self.log(f"[Pipeline] {line}", "FOUND")
                    # Extract subdomain from httpx output: https://sub.domain.com [200] ...
                    # Filter out 301, 404, 503 responses
                    if any(x in line for x in ["[301]", "[404]", "[503]"]):
                        continue
                    if line.startswith("http"):
                        parts = line.split()
                        if parts:
                            from urllib.parse import urlparse
                            parsed = urlparse(parts[0])
                            sub = parsed.netloc.split(":")[0]
                            if sub:
                                self.subdomain_found.emit(line)  # emit full httpx line
                    else:
                        self.subdomain_found.emit(line.split(":")[0])

            for line in proc.stderr:
                line = line.strip()
                if line and "[INF]" in line:
                    self.log(line, "INFO")

            proc.wait()
        except Exception as e:
            self.log(f"ShuffleDNS pipeline error: {e}", "WARN")


# ============ RECON: PORT SCANNER ============
class PortScanner(BaseThread):
    port_found = pyqtSignal(str, int, str)

    COMMON_PORTS = {
        80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        3000: "Node/React", 5000: "Flask/Dev", 9000: "PHP-FPM",
        22: "SSH", 21: "FTP", 25: "SMTP", 3306: "MySQL",
        5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
        9200: "Elasticsearch", 8888: "Jupyter",
    }

    def __init__(self, hosts, ports=None):
        super().__init__()
        self.hosts = hosts if isinstance(hosts, list) else [hosts]
        self.ports = ports or list(self.COMMON_PORTS.keys())

    def run(self):
        try:
            self.log(f"Port scan starting on {len(self.hosts)} hosts...")
            for host in self.hosts:
                self._scan_host(host)
            self.log("Port scan complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))

    def _scan_host(self, host):
        self.log(f"Scanning {host}...")
        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    service = self.COMMON_PORTS.get(port, "Unknown")
                    self.log(f"  OPEN {host}:{port} ({service})", "FOUND")
                    self.port_found.emit(host, port, service)
            except Exception:
                pass


# ============ RECON: SUBZY (TAKEOVER) ============
class SubzyScanner(BaseThread):
    takeover_found = pyqtSignal(str, str)

    def __init__(self, subdomains):
        super().__init__()
        self.subdomains = subdomains

    def run(self):
        try:
            self.log("Checking for subdomain takeover with Subzy...")
            import tempfile, os

            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(self.subdomains))
                tmp = f.name

            proc = subprocess.Popen(
                ["subzy", "run", "--targets", tmp],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            for line in proc.stdout:
                line = line.strip()
                if line and "VULNERABLE" in line.upper():
                    self.log(f"[TAKEOVER] {line}", "VULN")
                    self.takeover_found.emit(line, "high")
                elif line:
                    self.log(line)
            proc.wait()
            os.unlink(tmp)
            self.log("Subzy scan complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))


# ============ API TESTING ============
class APIScanner(BaseThread):
    endpoint_found = pyqtSignal(str, str, int, int, int)
    vuln_found = pyqtSignal(str, str, str, str)

    def __init__(self, target, wordlist=None, methods=None,
                 headers=None, delay=200, filter_codes=None):
        super().__init__()
        self.target = target.rstrip("/")
        self.wordlist = wordlist or API_ENDPOINTS
        self.methods = methods or ["GET", "POST"]
        self.headers = headers or {}
        self.delay = delay / 1000
        self.filter_codes = filter_codes or [200, 301, 302, 400, 401, 403, 405, 500]
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            session = requests.Session()
            session.verify = False
            session.headers.update(self.headers)

            total = len(self.wordlist) * len(self.methods)
            done = 0

            self.log(f"API scan: {self.target} — {len(self.wordlist)} endpoints × {len(self.methods)} methods")

            for endpoint in self.wordlist:
                if self._stop:
                    break
                for method in self.methods:
                    if self._stop:
                        break
                    url = self.target + endpoint
                    try:
                        start = time.time()
                        resp = session.request(method, url, timeout=8, allow_redirects=False)
                        elapsed = int((time.time() - start) * 1000)

                        if resp.status_code in self.filter_codes:
                            self.log(f"{method} {endpoint} → {resp.status_code} ({elapsed}ms, {len(resp.content)}b)", "FOUND")
                            self.endpoint_found.emit(url, method, resp.status_code, len(resp.content), elapsed)

                            # Check for interesting headers
                            self._check_cors(url, resp)

                    except requests.exceptions.Timeout:
                        pass
                    except Exception as e:
                        pass

                    done += 1
                    time.sleep(self.delay)

            self.log("API scan complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))

    def _check_cors(self, url, resp):
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao and acac.lower() == "true":
            self.log(f"[CORS] Potential misconfiguration at {url} — ACAO: {acao}", "VULN")
            self.vuln_found.emit("CORS Misconfiguration", "high", url,
                                  f"ACAO: {acao} | Credentials: {acac}")


# ============ PARAM FUZZER ============
class ParamFuzzer(BaseThread):
    param_found = pyqtSignal(str, str, int, int)

    def __init__(self, target, endpoint, params=None, value="1", headers=None):
        super().__init__()
        self.target = target.rstrip("/")
        self.endpoint = endpoint
        self.params = params or HIDDEN_PARAMS
        self.value = value
        self.headers = headers or {}

    def run(self):
        try:
            session = requests.Session()
            session.verify = False
            session.headers.update(self.headers)

            self.log(f"Param fuzzing: {self.endpoint} with {len(self.params)} params")

            baseline_url = self.target + self.endpoint
            try:
                baseline = session.get(baseline_url, timeout=5)
                baseline_len = len(baseline.content)
            except:
                baseline_len = None

            for param in self.params:
                param = param.strip()
                if not param:
                    continue
                url = f"{self.target}{self.endpoint}?{param}={self.value}"
                try:
                    resp = session.get(url, timeout=5)
                    length_diff = abs(len(resp.content) - baseline_len) if baseline_len else 0

                    if resp.status_code not in [404, 503] or length_diff > 50:
                        self.log(f"?{param}={self.value} → {resp.status_code} ({len(resp.content)}b)", "FOUND")
                        self.param_found.emit(param, url, resp.status_code, len(resp.content))
                except:
                    pass
                time.sleep(0.1)

            self.log("Param fuzzing complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))


# ============ IDOR SCANNER ============
class IDORScanner(BaseThread):
    idor_found = pyqtSignal(int, int, int, bool)

    def __init__(self, target, endpoint, method="GET", start=1, end=50,
                 my_id=None, headers=None, delay=100):
        super().__init__()
        self.target = target.rstrip("/")
        self.endpoint = endpoint
        self.method = method
        self.start = start
        self.end = end
        self.my_id = my_id
        self.headers = headers or {}
        self.delay = delay / 1000
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            session = requests.Session()
            session.verify = False
            session.headers.update(self.headers)

            baseline_len = None
            if self.my_id:
                url = self.target + self.endpoint.replace("FUZZ", str(self.my_id))
                try:
                    resp = session.request(self.method, url, timeout=5)
                    baseline_len = len(resp.content)
                    self.log(f"Baseline (ID {self.my_id}): {resp.status_code}, {baseline_len}b")
                except:
                    pass

            self.log(f"IDOR scan: {self.endpoint} IDs {self.start}-{self.end}")

            for id_val in range(self.start, self.end + 1):
                if self._stop:
                    break
                if id_val == self.my_id:
                    continue

                url = self.target + self.endpoint.replace("FUZZ", str(id_val))
                try:
                    resp = session.request(self.method, url, timeout=5)
                    if resp.status_code == 200:
                        is_diff = baseline_len is not None and abs(len(resp.content) - baseline_len) > 10
                        self.log(f"ID {id_val} → 200 ({len(resp.content)}b) {'🚨 DIFFERENT!' if is_diff else ''}", "FOUND" if is_diff else "INFO")
                        self.idor_found.emit(id_val, resp.status_code, len(resp.content), is_diff)
                except:
                    pass
                time.sleep(self.delay)

            self.log("IDOR scan complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))


# ============ CORS TESTER ============
class CORSTester(BaseThread):
    cors_result = pyqtSignal(str, str, str, bool)

    DEFAULT_ORIGINS = [
        "null", "https://evil.com", "https://attacker.com",
        "http://localhost", "https://notevil.target.com",
    ]

    def __init__(self, url, origins=None, headers=None):
        super().__init__()
        self.url = url
        self.origins = origins or self.DEFAULT_ORIGINS
        self.headers = headers or {}

    def run(self):
        try:
            session = requests.Session()
            session.verify = False

            self.log(f"CORS test: {self.url}")

            for origin in self.origins:
                h = {**self.headers, "Origin": origin}
                try:
                    resp = session.get(self.url, headers=h, timeout=5)
                    acao = resp.headers.get("Access-Control-Allow-Origin", "NOT PRESENT")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "false")
                    vulnerable = (acao == origin or acao == "*") and acac.lower() == "true"
                    
                    status = "🚨 VULNERABLE" if vulnerable else ("⚠️ CHECK" if acao != "NOT PRESENT" else "✓ Safe")
                    self.log(f"Origin: {origin} → ACAO: {acao} | Creds: {acac} | {status}",
                             "VULN" if vulnerable else "INFO")
                    self.cors_result.emit(origin, acao, acac, vulnerable)
                except Exception as e:
                    self.log(f"Error testing {origin}: {e}", "WARN")

            self.log("CORS test complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))


# ============ JWT ANALYZER ============
class JWTAnalyzer:
    @staticmethod
    def analyze(token):
        import base64
        try:
            parts = token.strip().split(".")
            if len(parts) < 2:
                return None, "Invalid JWT format"

            def decode(part):
                pad = 4 - len(part) % 4
                if pad != 4:
                    part += "=" * pad
                return json.loads(base64.urlsafe_b64decode(part))

            header = decode(parts[0])
            payload = decode(parts[1])

            # Generate alg:none
            none_h = {**header, "alg": "none"}
            enc_h = base64.urlsafe_b64encode(json.dumps(none_h, separators=(',', ':')).encode()).rstrip(b'=').decode()
            enc_p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).rstrip(b'=').decode()
            attack = f"{enc_h}.{enc_p}."

            return {"header": header, "payload": payload, "attack_token": attack}, None
        except Exception as e:
            return None, str(e)


# ============ NUCLEI SCANNER ============
class NucleiScanner(BaseThread):
    vuln_found = pyqtSignal(str, str, str, str)

    TEMPLATES = {
        "sqli": "vulnerabilities/sql-injection",
        "xss": "vulnerabilities/xss",
        "ssrf": "vulnerabilities/ssrf",
        "xxe": "vulnerabilities/xxe",
        "cors": "vulnerabilities/cors",
        "ssti": "vulnerabilities/ssti",
    }

    TEMPLATE_BASE = "/home/kali/nuclei-templates"

    def __init__(self, target, template_types=None, custom_wordlist=None, rate_limit=50):
        super().__init__()
        self.target = target
        self.template_types = template_types or ["sqli", "xss", "cors"]
        self.custom_wordlist = custom_wordlist
        self.rate_limit = rate_limit

    def stop(self):
        self._stop = True

    def run(self):
        self._stop = False
        try:
            self.log(f"Nuclei scan: {self.target}")

            templates = []
            for t in self.template_types:
                if t in self.TEMPLATES:
                    full_path = f"{self.TEMPLATE_BASE}/{self.TEMPLATES[t]}"
                    templates.extend(["-t", full_path])

            # v3.8.0 compatible — no -json flag
            cmd = ["nuclei", "--target", self.target,
                   "-rl", str(self.rate_limit),
                   "-nc", "-silent"] 

            # custom_wordlist not used in simple mode

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                # v3 output: [severity] [template-id] url
                self.log(line)

                severity = "info"
                for s in ["critical", "high", "medium", "low"]:
                    if f"[{s}]" in line.lower():
                        severity = s
                        break

                parts = line.split()
                url = parts[-1] if parts else self.target

                if any(f"[{s}]" in line.lower() for s in ["critical","high","medium","low","info"]):
                    self.log(f"FINDING: {line}", "VULN")
                    self.vuln_found.emit(line, severity, url, "")

            for line in proc.stderr:
                line = line.strip()
                if line and "[INF]" not in line and "[WRN]" not in line:
                    self.log(line)

            proc.wait()
            self.log("Nuclei scan complete", "INFO")
            self.finished_signal.emit()
        except FileNotFoundError:
            self.error_signal.emit("nuclei not found in PATH")
        except Exception as e:
            self.error_signal.emit(str(e))


# ============ OSINT ============
class OSINTScanner(BaseThread):
    result_found = pyqtSignal(str, str)

    def __init__(self, domain, shodan_key=None, censys_id=None, censys_secret=None):
        super().__init__()
        self.domain = domain
        self.shodan_key = shodan_key
        self.censys_id = censys_id
        self.censys_secret = censys_secret

    def run(self):
        try:
            self.log(f"OSINT scan: {self.domain}")
            self._crtsh()
            self._dns_lookup()
            self._whois()
            if self.shodan_key:
                self._shodan()
            self.log("OSINT complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))

    def _crtsh(self):
        self.log("Querying crt.sh for certificates...")
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=10
            )
            if resp.status_code == 200:
                certs = resp.json()
                subdomains = set()
                for cert in certs:
                    names = cert.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lstrip("*.")
                        if self.domain in name and name not in subdomains:
                            subdomains.add(name)
                            self.log(f"[crt.sh] {name}", "FOUND")
                            self.result_found.emit("subdomain", name)
                self.log(f"crt.sh found {len(subdomains)} unique subdomains")
        except Exception as e:
            self.log(f"crt.sh error: {e}", "WARN")

    def _dns_lookup(self):
        self.log("DNS lookup...")
        try:
            import subprocess
            for rtype in ["A", "MX", "TXT", "NS", "CNAME"]:
                proc = subprocess.run(
                    ["dig", "+short", rtype, self.domain],
                    capture_output=True, text=True, timeout=5
                )
                for line in proc.stdout.strip().split("\n"):
                    if line.strip():
                        self.log(f"[DNS {rtype}] {line.strip()}", "FOUND")
                        self.result_found.emit(f"dns_{rtype.lower()}", line.strip())
        except Exception as e:
            self.log(f"DNS error: {e}", "WARN")

    def _whois(self):
        self.log("Whois lookup...")
        try:
            proc = subprocess.run(
                ["whois", self.domain],
                capture_output=True, text=True, timeout=10
            )
            important_fields = ["Registrar:", "Creation Date:", "Updated Date:",
                                 "Registrant:", "Name Server:"]
            for line in proc.stdout.split("\n"):
                for field in important_fields:
                    if field.lower() in line.lower():
                        self.log(f"[Whois] {line.strip()}", "INFO")
                        self.result_found.emit("whois", line.strip())
                        break
        except Exception as e:
            self.log(f"Whois error: {e}", "WARN")

    def _shodan(self):
        self.log("Querying Shodan...")
        try:
            resp = requests.get(
                f"https://api.shodan.io/dns/resolve?hostnames={self.domain}&key={self.shodan_key}",
                timeout=10
            )
            if resp.status_code == 200:
                ip = resp.json().get(self.domain)
                if ip:
                    self.log(f"[Shodan] IP: {ip}", "FOUND")
                    host_resp = requests.get(
                        f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}",
                        timeout=10
                    )
                    if host_resp.status_code == 200:
                        data = host_resp.json()
                        ports = data.get("ports", [])
                        self.log(f"[Shodan] Open ports: {ports}", "FOUND")
                        self.result_found.emit("shodan_ports", str(ports))
                        for item in data.get("data", []):
                            banner = item.get("data", "")[:100]
                            self.log(f"[Shodan] Port {item.get('port')}: {banner}", "INFO")
        except Exception as e:
            self.log(f"Shodan error: {e}", "WARN")


# ============ GOOGLE DORKING ============
class GoogleDorker:
    @staticmethod
    def get_dorks(domain):
        result = []
        for category, dorks in GOOGLE_DORKS:
            for dork in dorks:
                query = dork.replace("{domain}", domain)
                url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
                result.append((category, query, url))
        return result

    @staticmethod
    def open_dork(url):
        webbrowser.open(url)


# ============ NAABU PORT SCANNER ============
class NaabuScanner(BaseThread):
    port_found = pyqtSignal(str, str)

    def __init__(self, targets, ports="top-100"):
        super().__init__()
        self.targets = targets
        self.ports = ports

    def run(self):
        try:
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(self.targets))
                tmp = f.name

            self.log(f"Naabu port scan on {len(self.targets)} hosts...")
            cmd = ["naabu", "-list", tmp, f"-ports", self.ports,
                   "-exclude-ports", "9999", "-silent"]

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            for line in proc.stdout:
                line = line.strip()
                if line:
                    self.log(f"[Naabu] {line}", "FOUND")
                    self.port_found.emit(line, "open")
            proc.wait()
            os.unlink(tmp)
            self.log("Naabu scan complete", "INFO")
            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))
