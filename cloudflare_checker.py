import requests
import socket
import dns.resolver
from urllib.parse import urlparse
import re

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Partial Cloudflare IPv4 prefixes for demo (πλήρης λίστα μπορεί να προστεθεί)
CLOUDFLARE_IP_RANGES = [
    "173.245.", "103.21.", "103.22.", "103.31.", "141.101.",
    "108.162.", "190.93.", "188.114.", "197.234.", "198.41.",
    "162.158.", "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "104.22.", "104.23.", "104.24."
]

# Common Cloudflare datacenter codes from cf-ray header
CF_DATACENTER_CODES = {
    "LHR", "AMS", "SFO", "IAD", "ORD", "DFW", "DEN", "LAX",
    "SEA", "HKG", "SIN", "CDG", "FRA", "TLV", "MAD", "MIA",
    "BOS", "JFK", "EWR", "YYZ", "GRU"
}

def extract_domain(url):
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def ip_in_cloudflare_ranges(ip):
    for prefix in CLOUDFLARE_IP_RANGES:
        if ip.startswith(prefix):
            return True
    return False

def check_http_headers(url):
    print(f"{CYAN}\n[HTTP CHECK] Inspecting response headers...{RESET}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        hdrs = response.headers
        cookies = response.cookies

        found_cf = False

        # Basic Cloudflare headers & cookies from before
        basic_cf_headers = ['cf-ray', 'cf-cache-status', 'cf-request-id', 'cf-visitor', 'cf-ipcountry', 'cf-connecting-ip', 'expect-ct', 'nel', 'report-to']
        basic_cf_cookies = ['__cfduid', '__cflb']

        # Check for Cloudflare server header variants
        server = hdrs.get('server', '').lower()
        if 'cloudflare' in server:
            print(f"{GREEN}✅ Header 'server' indicates Cloudflare: {server}{RESET}")
            found_cf = True

        # Check existence of Cloudflare-specific headers
        for h in hdrs:
            hl = h.lower()
            if hl in basic_cf_headers:
                print(f"{GREEN}✅ Found Cloudflare header: {h} => {hdrs[h]}{RESET}")
                found_cf = True

        # Regex check for cf-ray pattern: hex + datacenter code
        cf_ray = hdrs.get('cf-ray')
        if cf_ray:
            # pattern: hex + "-" + datacenter code, e.g. "7f9e2a1bfb8c9e12-LHR"
            if re.match(r"^[0-9a-f]{16}-[A-Z]{3}$", cf_ray):
                dc = cf_ray[-3:]
                if dc in CF_DATACENTER_CODES:
                    print(f"{GREEN}✅ Valid cf-ray header with datacenter code: {cf_ray}{RESET}")
                    found_cf = True
                else:
                    print(f"{YELLOW}⚠️ cf-ray header datacenter code '{dc}' not recognized, but header exists: {cf_ray}{RESET}")

        # Check for Cloudflare cookies
        for c in cookies:
            if c in basic_cf_cookies:
                print(f"{GREEN}✅ Found Cloudflare cookie: {c}{RESET}")
                found_cf = True

        # Check WAF block page hints in body text
        body = response.text.lower()
        if "cloudflare" in body and ("error" in body or "attention required" in body):
            print(f"{GREEN}✅ Response body contains Cloudflare WAF signature{RESET}")
            found_cf = True

        # Check rate limiting status code
        if response.status_code == 429:
            print(f"{YELLOW}⚠️ Response status 429 Too Many Requests - likely Cloudflare rate limiting{RESET}")
            found_cf = True

        # Check CF-Cache-Status values for expected keywords
        cf_cache_status = hdrs.get('cf-cache-status')
        if cf_cache_status:
            expected_statuses = {"HIT", "MISS", "EXPIRED", "DYNAMIC", "BYPASS"}
            if cf_cache_status.upper() in expected_statuses:
                print(f"{GREEN}✅ CF-Cache-Status header with value: {cf_cache_status}{RESET}")
                found_cf = True
            else:
                print(f"{YELLOW}⚠️ CF-Cache-Status header has unusual value: {cf_cache_status}{RESET}")

        # Additional check for HTTP/3 support (via Alt-Svc header)
        alt_svc = hdrs.get('alt-svc', '')
        if "h3" in alt_svc:
            print(f"{GREEN}✅ Alt-Svc header indicates HTTP/3 support, common with Cloudflare: {alt_svc}{RESET}")
            found_cf = True

        if found_cf:
            return True
        else:
            print(f"{RED}❌ No Cloudflare indicators found in HTTP headers, cookies or body.{RESET}")
            return False

    except requests.RequestException as e:
        print(f"{RED}[ERROR] Failed to fetch headers: {e}{RESET}")
        return None

def check_dns(domain):
    print(f"{CYAN}\n[DNS CHECK] Inspecting A record and nameservers...{RESET}")
    ip = None
    try:
        ip = socket.gethostbyname(domain)
        print(f"Resolved IP: {ip}")
    except Exception as e:
        print(f"{YELLOW}[WARN] socket.gethostbyname failed: {e}, trying dns.resolver fallback...{RESET}")
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                ip = rdata.to_text()
                print(f"Resolved IP (dns.resolver): {ip}")
                break
        except Exception as e2:
            print(f"{RED}[ERROR] dns.resolver A record lookup failed: {e2}{RESET}")
            ip = None

    if ip:
        if ip_in_cloudflare_ranges(ip):
            print(f"{GREEN}✅ IP address {ip} is within known Cloudflare IP ranges.{RESET}")
        else:
            print(f"{YELLOW}⚠️ IP address {ip} is NOT within known Cloudflare IP ranges.{RESET}")
    else:
        print(f"{YELLOW}⚠️ Unable to resolve IP address, skipping IP-based Cloudflare check.{RESET}")

    # Nameserver check on root domain
    try:
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            root_domain = ".".join(domain_parts[-2:])
        else:
            root_domain = domain

        ns_records = dns.resolver.resolve(root_domain, 'NS')
        found_cf_ns = False
        for ns in ns_records:
            ns_text = ns.to_text().lower()
            if "cloudflare" in ns_text:
                print(f"{GREEN}✅ Nameserver {ns} indicates Cloudflare.{RESET}")
                found_cf_ns = True
        if not found_cf_ns:
            print(f"{RED}❌ No Cloudflare nameservers detected.{RESET}")
        return found_cf_ns

    except Exception as e:
        print(f"{RED}[ERROR] DNS nameserver lookup failed: {e}{RESET}")
        return None

if __name__ == "__main__":
    url = input("Enter a URL or domain (e.g. https://example.com): ").strip()
    domain = extract_domain(url)

    print(f"\n🔍 Checking domain: {domain}")
    print("-" * 50)

    http_result = check_http_headers(url)
    dns_result = check_dns(domain)

    print(f"\n🔎 Final verdict:")
    if http_result or dns_result:
        print(f"{GREEN}✅ The site appears to be using Cloudflare.{RESET}")
    elif http_result is False and dns_result is False:
        print(f"{RED}❌ The site does not appear to be using Cloudflare.{RESET}")
    else:
        print(f"{YELLOW}⚠️ Could not determine with certainty.{RESET}")
