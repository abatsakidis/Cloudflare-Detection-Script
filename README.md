
# Cloudflare Detection Script

## Description
This Python script checks whether a given website or domain is protected by Cloudflare. It performs multiple checks, including:

- Inspecting HTTP response headers and cookies for Cloudflare indicators
- Checking DNS A records and nameservers for Cloudflare
- Verifying if the resolved IP falls within known Cloudflare IP ranges
- Detecting Cloudflare datacenter codes in response headers
- Analyzing response body for Cloudflare WAF signatures
- Checking rate limiting status codes related to Cloudflare
- Verifying HTTP/3 support via Alt-Svc headers

The script outputs detailed diagnostic information using color-coded console messages for easy understanding.

## Features
- HTTP header and cookie inspection for Cloudflare-specific fields
- DNS resolution and nameserver check with fallback
- IP range validation against known Cloudflare IP prefixes
- Cloudflare datacenter validation through cf-ray header
- WAF signature detection in response body
- Rate limiting detection based on HTTP status code 429
- Detection of HTTP/3 support common to Cloudflare sites
- User-friendly color-coded terminal output without external dependencies

## Requirements
- Python 3.x
- Python packages:
  - `requests`
  - `dnspython`

If you cannot use `pip install`, you might need to install dependencies manually or via your system package manager.

## How to use

1. Clone or download the script file `cloudflare.py`.

2. Install required packages:
   ```
   pip install requests dnspython
   ```

3. Run the script:
   ```
   python3 cloudflare.py
   ```

4. Enter a URL or domain when prompted (e.g., `https://example.com` or `example.com`).

5. Review the color-coded output to determine if the site uses Cloudflare.

---

## Notes

- The script uses basic IP prefix matching for Cloudflare IPs; a complete list can be updated manually.
- Some checks rely on HTTP response headers, which can be spoofed but usually are reliable indicators.
- DNS checks verify nameservers to detect if the domain delegates DNS to Cloudflare.
- Response body inspection helps identify Cloudflare's WAF challenge pages.
- This tool is designed for educational and diagnostic use only.

---

**Author:** Your Name  
**License:** MIT  
