#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║           WebRecon — Website Recon Tool              ║
║         By: Mosaab Afrit (TheBoss01011)              ║
║       github.com/TheBoss01011/WebRecon               ║
╚══════════════════════════════════════════════════════╝
  Gather information about any website in seconds.
  For educational purposes only.
"""

import socket
import ssl
import urllib.request
import urllib.error
import json
import sys
import time
from datetime import datetime


# ─────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    LINE   = f"\033[90m{'─' * 52}\033[0m"


# ─────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────
def banner():
    print(f"""
{C.CYAN}{C.BOLD}
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.RESET}
{C.YELLOW}      Website Reconnaissance Tool — by Mosaab Afrit{C.RESET}
{C.GRAY}      github.com/TheBoss01011  |  For educational use only{C.RESET}
""")


# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def section(title):
    print(f"\n{C.LINE}")
    print(f"  {C.BOLD}{C.BLUE}[ {title} ]{C.RESET}")
    print(C.LINE)

def ok(label, value):
    print(f"  {C.GREEN}✔{C.RESET}  {C.WHITE}{label:<22}{C.RESET} {C.CYAN}{value}{C.RESET}")

def fail(label, reason="Not available"):
    print(f"  {C.RED}✘{C.RESET}  {C.WHITE}{label:<22}{C.RESET} {C.GRAY}{reason}{C.RESET}")

def info(msg):
    print(f"  {C.GRAY}→ {msg}{C.RESET}")

def clean_domain(target):
    target = target.strip().lower()
    target = target.replace("https://", "").replace("http://", "")
    target = target.split("/")[0]
    return target


# ─────────────────────────────────────────
#  MODULE 1: DNS & IP
# ─────────────────────────────────────────
def get_dns_ip(domain):
    section("DNS & IP Information")
    try:
        ip = socket.gethostbyname(domain)
        ok("Domain", domain)
        ok("IP Address", ip)

        # Reverse DNS
        try:
            reverse = socket.gethostbyaddr(ip)[0]
            ok("Reverse DNS", reverse)
        except:
            fail("Reverse DNS")

        # All IPs
        try:
            all_ips = socket.getaddrinfo(domain, None)
            unique = list(set([x[4][0] for x in all_ips]))
            ok("All IPs found", ", ".join(unique))
        except:
            pass

        return ip
    except socket.gaierror as e:
        fail("DNS Resolution", str(e))
        return None


# ─────────────────────────────────────────
#  MODULE 2: Port Scanner
# ─────────────────────────────────────────
PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 587: "SMTP-TLS", 993: "IMAPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

def scan_ports(ip):
    section("Open Ports")
    if not ip:
        fail("Port scan", "No IP available")
        return

    open_ports = []
    info(f"Scanning {len(PORTS)} common ports on {ip}...")
    print()

    for port, service in PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"  {C.GREEN}✔  {port:<6} OPEN    [{service}]{C.RESET}")
                open_ports.append(port)
            sock.close()
        except:
            pass

    if not open_ports:
        print(f"  {C.GRAY}No open ports found (firewall may be active){C.RESET}")
    else:
        print(f"\n  {C.YELLOW}→ {len(open_ports)} open port(s) detected{C.RESET}")


# ─────────────────────────────────────────
#  MODULE 3: HTTP Headers
# ─────────────────────────────────────────
INTERESTING_HEADERS = [
    "server", "x-powered-by", "content-type", "x-frame-options",
    "strict-transport-security", "content-security-policy",
    "x-xss-protection", "x-content-type-options", "set-cookie"
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-xss-protection",
    "x-content-type-options"
]

def get_http_headers(domain):
    section("HTTP Headers & Security")
    found_security = []

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "WebRecon/1.0"})
            response = urllib.request.urlopen(req, timeout=5)
            headers = dict(response.headers)

            ok("Status Code", str(response.status))
            ok("URL", url)
            print()

            for key, val in headers.items():
                if key.lower() in INTERESTING_HEADERS:
                    label = key.title()
                    # Truncate long values
                    display = val if len(val) < 60 else val[:57] + "..."
                    ok(label, display)
                if key.lower() in SECURITY_HEADERS:
                    found_security.append(key.lower())

            # Security report
            print()
            missing = [h for h in SECURITY_HEADERS if h not in found_security]
            if missing:
                print(f"  {C.YELLOW}⚠  Missing security headers:{C.RESET}")
                for h in missing:
                    print(f"     {C.RED}✘  {h}{C.RESET}")
            else:
                print(f"  {C.GREEN}✔  All major security headers present!{C.RESET}")

            return
        except Exception as e:
            continue

    fail("HTTP Headers", "Could not connect")


# ─────────────────────────────────────────
#  MODULE 4: SSL Certificate
# ─────────────────────────────────────────
def get_ssl_info(domain):
    section("SSL Certificate")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))

        ok("Common Name",     subject.get("commonName", "N/A"))
        ok("Organization",    subject.get("organizationName", "N/A"))
        ok("Issued By",       issuer.get("organizationName", "N/A"))
        ok("Valid From",      cert.get("notBefore", "N/A"))
        ok("Valid Until",     cert.get("notAfter", "N/A"))

        # Check SANs
        sans = cert.get("subjectAltName", [])
        if sans:
            domains = [v for t, v in sans if t == "DNS"]
            ok("Alt Names (SANs)", f"{len(domains)} domain(s)")
            for d in domains[:5]:
                print(f"     {C.GRAY}→ {d}{C.RESET}")
            if len(domains) > 5:
                print(f"     {C.GRAY}→ ... and {len(domains)-5} more{C.RESET}")

    except ssl.SSLError as e:
        fail("SSL", f"SSL Error: {e}")
    except Exception as e:
        fail("SSL Certificate", str(e))


# ─────────────────────────────────────────
#  MODULE 5: Common Subdomains
# ─────────────────────────────────────────
SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev",
    "staging", "blog", "shop", "vpn", "cdn", "portal",
    "remote", "test", "support", "login", "app", "dashboard"
]

def check_subdomains(domain):
    section("Subdomain Discovery")
    info(f"Checking {len(SUBDOMAINS)} common subdomains...")
    print()

    found = []
    for sub in SUBDOMAINS:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            print(f"  {C.GREEN}✔  {full:<35} → {ip}{C.RESET}")
            found.append(full)
        except:
            print(f"  {C.GRAY}✘  {full}{C.RESET}")

    print(f"\n  {C.YELLOW}→ {len(found)} subdomain(s) found{C.RESET}")


# ─────────────────────────────────────────
#  MODULE 6: IP Geolocation
# ─────────────────────────────────────────
def get_geolocation(ip):
    section("IP Geolocation")
    if not ip:
        fail("Geolocation", "No IP available")
        return
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon"
        req = urllib.request.Request(url, headers={"User-Agent": "WebRecon/1.0"})
        response = urllib.request.urlopen(req, timeout=5)
        data = json.loads(response.read().decode())

        if data.get("status") == "success":
            ok("Country",    data.get("country", "N/A"))
            ok("Region",     data.get("regionName", "N/A"))
            ok("City",       data.get("city", "N/A"))
            ok("ISP",        data.get("isp", "N/A"))
            ok("Org",        data.get("org", "N/A"))
            ok("ASN",        data.get("as", "N/A"))
            ok("Coordinates", f"{data.get('lat')}, {data.get('lon')}")
        else:
            fail("Geolocation", "API returned no data")
    except Exception as e:
        fail("Geolocation", str(e))


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
def run_recon(target):
    domain = clean_domain(target)
    start  = time.time()

    print(f"\n{C.BOLD}{C.WHITE}  Target  : {C.CYAN}{domain}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  Started : {C.GRAY}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")

    ip = get_dns_ip(domain)
    get_geolocation(ip)
    scan_ports(ip)
    get_http_headers(domain)
    get_ssl_info(domain)
    check_subdomains(domain)

    elapsed = round(time.time() - start, 2)
    print(f"\n{C.LINE}")
    print(f"  {C.GREEN}{C.BOLD}✔ Recon complete in {elapsed}s{C.RESET}")
    print(f"{C.LINE}\n")


def main():
    banner()

    if len(sys.argv) > 1:
        # Run directly: python webrecon.py google.com
        run_recon(sys.argv[1])
    else:
        # Interactive mode
        while True:
            print(f"\n{C.BOLD}{C.WHITE}  Enter a domain to scan (or 'exit' to quit){C.RESET}")
            target = input(f"  {C.YELLOW}>> {C.RESET}").strip()

            if target.lower() in ("exit", "quit", "q", "0"):
                print(f"\n  {C.CYAN}Stay curious. Stay secure. 🔐{C.RESET}\n")
                break
            elif target:
                run_recon(target)


if __name__ == "__main__":
    main()
