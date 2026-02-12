# webvulnscanner
# Vulnerability Scanner

A web app that scans a target URL for security issues and generates a **PDF report**. Includes live log, severity summary, export (JSON/CSV), and scan history. **Use only on systems you are authorized to test.**

---

## Features

| Category | What it does |
|----------|--------------|
| **Target & reachability** | Validates the URL (ping/HEAD) before scanning; shows “Invalid website” if unreachable. |
| **Target info** | Resolves IP, WHOIS excerpt, requester IP. |
| **SSL/TLS** | Certificate details, validity, fingerprint; TLS protocol and cipher (flags weak/deprecated). |
| **Security headers** | Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. |
| **Technologies** | Detects server, X-Powered-By, CMS (WordPress/Joomla/Drupal), Laravel, React/Vue from headers and HTML. |
| **Robots & sitemap** | Fetches `/robots.txt`, parses Sitemap and Disallow rules. |
| **Sensitive paths** | Probes for `.env`, `.git/config`, `backup.sql`, `phpinfo.php`, `wp-config.php`, etc. |
| **Open redirects** | Tests common parameters (redirect, url, next, returnUrl, etc.) with a canary URL. |
| **Directory & admin** | Wordlist-based discovery of paths and possible admin panels (with delay to reduce WAF/block risk). |
| **SQL injection** | Error-based detection using the [HitmanAlharbi SQL-injections-simple](https://github.com/HitmanAlharbi/Wordlists) wordlist; only reports when an SQL error appears in the response. |
| **XSS** | Reflected XSS testing with a payload wordlist. |
| **Nmap** | Open ports and service versions (if Nmap is installed). |
| **CVE lookup** | Finds related CVEs and remediation (optional NVD API key for higher rate limits). |
| **Subdomains** | Optional discovery (www, mail, api, etc.) in **Full** profile only. |
| **PDF report** | Executive summary, severity counts, and sections for all findings plus remediation. |
| **Export** | Download last scan as JSON or CSV (summary + severity). |
| **Scan history** | Last N scans (target, date, success/fail, report link). |
| **Options** | Scan profile (Quick / Full), optional HTTP Basic auth, exclude paths, rate limiting, optional webhook on completion. |

---

## What the scan does (order of operations)

1. **URL check** – HEAD request to confirm the site is reachable.  
2. **Target info** – IP resolution, WHOIS.  
3. **SSL certificate** – For HTTPS: subject, issuer, validity, fingerprint.  
4. **Security headers** – Present/missing and recommendations.  
5. **TLS quality** – Protocol and cipher; flags weak/deprecated.  
6. **Technology detection** – Server, CMS, frameworks.  
7. **Robots.txt & sitemap** – Fetch and parse.  
8. **Sensitive paths** – Probe known dangerous paths.  
9. **Open redirect** – Test common redirect parameters.  
10. **XSS** – Reflected XSS with wordlist payloads.  
11. **SQL injection** – Error-based testing with SQL payload wordlist (stops at first confirmed error per URL).  
12. **Admin finder** – Wordlist of admin paths.  
13. **Directory scan** – Wordlist of paths/files.  
14. **Nmap** – Port and version scan (if available).  
15. **CVE lookup** – From detected services/versions.  
16. **Subdomains** – Only in **Full** profile.  
17. **PDF report** – Generated with executive summary, severity, and all sections.  
18. **Webhook** – If configured, POSTs result summary.  
19. **History** – Entry added for this scan.

Quick profile uses smaller wordlists and skips subdomain discovery; Full runs everything.

---

## Requirements

- **PHP 7.4+** with extensions: `curl`, `json`, `mbstring`
- **Composer** (for dependencies)
- **Nmap** (optional) – for port/service scanning; scan works without it
- **Web server** – Apache, Nginx, or PHP built-in server
- **Writable directories** – `reports/` and `data/` (for rate limit and scan history)

---

## Installation

1. **Get the code**  
   Clone or copy the project to your web root (e.g. `htdocs/scanner` or Laragon `www/scanner`).

2. **Install PHP dependencies**
   ```bash
   cd scanner
   composer install
   ```

3. **Create writable directories** (if they don’t exist)
   ```bash
   mkdir -p reports data
   chmod 755 reports data
   ```
   Ensure the web server user can write to `reports/` and `data/`.

4. **Configure**  
   Copy or edit `config.php`:
   - **Nmap**: Set `NMAP_PATH` if Nmap is not on `PATH` (e.g. Windows: `C:\Program Files (x86)\Nmap\nmap.exe`).
   - **Timeouts**: `HTTP_TIMEOUT`, `NMAP_TIMEOUT`, `SCAN_MAX_EXECUTION_TIME` (0 = no PHP time limit).
   - **Wordlists**: Directory, admin, XSS, and SQL wordlists use URLs or local paths in config; optional local files go in `wordlists/`.
   - **Rate limit**: `RATE_LIMIT_SCANS_PER_HOUR` (0 = off).
   - **Webhook**: `WEBHOOK_URL` or env `SCAN_WEBHOOK_URL` for POST on scan completion.
   - **NVD API**: Optional `NVD_API_KEY` or env for CVE lookup (better rate limits).

5. **PHP/Apache (production)**  
   Increase `max_execution_time` and request timeouts if you run long scans. Point the document root to the project directory so `index.php` is the main entry.

6. **Run**  
   Open the site in a browser (e.g. `http://localhost/scanner/`).

---

## How to use

1. **Enter target URL** – e.g. `https://example.com`. The scanner will check that the site is reachable first.
2. **Invalid website** – If the URL can’t be reached, you’ll see “Invalid website” and no scan is run.
3. **Valid website** – A popup says the scan may take a while (“go make a coffee”); click **OK** to start.
4. **Scan profile** – Choose **Quick** (smaller wordlists, no subdomains) or **Full** (full wordlists + subdomain discovery).
5. **Optional** – Under “Optional: Auth & exclude paths” you can set HTTP Basic username/password and comma-separated paths to exclude from directory/admin scans.
6. **Run scan** – Click “Run scan & generate PDF”. Progress and a live log appear.
7. **Result** – When done: success/failure message, summary (counts and severity), link to **Download PDF report**, and **Export JSON** / **Export CSV** (last result).
8. **Scan history** – Below the form, the last N scans are listed with date, URL, status, and report link (when available).
9. **Rate limit** – If you exceed the configured scans per hour per IP, you’ll see “Rate limit exceeded. Try again later.”

---

## Configuration overview (`config.php`)

| Constant | Purpose |
|----------|---------|
| `SCANNER_BASE_URL` | Base URL of the scanner (for report links). |
| `HTTP_TIMEOUT`, `NMAP_TIMEOUT` | Request and Nmap timeouts. |
| `XSS_WORDLIST_URL` / `XSS_WORDLIST_PATH`, `XSS_MAX_PAYLOADS` | XSS payload wordlist. |
| `SQL_WORDLIST_URL` / `SQL_WORDLIST_PATH`, `SQL_MAX_PAYLOADS` | SQL injection payload wordlist (error-based). |
| `ADMIN_WORDLIST_*`, `ADMIN_MAX_PATHS` | Admin panel paths. |
| `DIR_SCAN_WORDLIST` | Directory/file paths. |
| `NVD_API_KEY` | Optional NVD API key for CVE lookup. |
| `NMAP_PATH` | Path to Nmap binary (empty = use `nmap` from PATH). |
| `SCAN_REQUEST_DELAY_MS` | Delay between directory/admin/SQL requests (reduces WAF/block risk). |
| `SCAN_PROFILE_DEFAULT` | Default profile: `quick` or `full`. |
| `WEBHOOK_URL` | Optional URL to POST scan result JSON. |
| `EXCLUDE_PATHS` | Default comma-separated paths to exclude. |
| `RATE_LIMIT_SCANS_PER_HOUR` | Max scans per IP per hour (0 = no limit). |
| `SCAN_HISTORY_SIZE` | Number of scan history entries (0 = disabled). |
| `SCAN_AUTH_BASIC_USER` / `SCAN_AUTH_BASIC_PASS` | Optional default HTTP Basic auth for target. |
| `REPORTS_DIR` | Where PDF reports are saved. |
| `ALLOWED_TARGETS` | Optional list of allowed hostnames (empty = any). |

---

## Project structure

```
scanner/
├── index.php              # Main UI (form, live log, result, export, history)
├── config.php             # All configuration
├── composer.json
├── api/
│   ├── check-url.php      # Validates target URL (HEAD) before scan
│   ├── run-scan.php       # Runs full scan, streams progress, returns result + report
│   └── scan-history.php   # Returns last N scans (JSON)
├── classes/
│   ├── ReportGenerator.php    # PDF report (TCPDF)
│   ├── DirectoryScanner.php    # Directory/file discovery
│   ├── SqlVulnScanner.php      # SQL injection (error-based, wordlist)
│   ├── XssScanner.php          # Reflected XSS
│   ├── NmapScanner.php         # Port/service scan
│   ├── CveLookup.php           # NVD CVE lookup
│   ├── SslChecker.php          # SSL certificate
│   ├── SecurityHeadersChecker.php
│   ├── TlsQualityChecker.php
│   ├── TechnologyDetector.php
│   ├── RobotsSitemapFetcher.php
│   ├── SensitivePathsChecker.php
│   ├── OpenRedirectScanner.php
│   ├── SubdomainFinder.php
│   ├── WhoisLookup.php
│   ├── RateLimiter.php
│   └── ScanHistory.php
├── wordlists/
│   ├── dirs.txt           # Directory scan paths (add your own or keep default)
│   ├── sql_injections.txt # Optional local cache of SQL wordlist
│   ├── xss.txt            # Optional local XSS wordlist
│   └── admin_panels.txt   # Optional local admin wordlist
├── reports/               # Generated PDFs (writable)
├── data/                  # Rate limit and scan_history.json (writable)
└── vendor/                # Composer dependencies (TCPDF, etc.)
```

---

## Legal

Only scan targets you own or have explicit permission to test. Unauthorized scanning may be illegal. The authors are not responsible for misuse of this software.
