# Vaelion-XSS

```
========================================
          Vaelion-XSS
    Cross Site Scripting Scanner
            By Vaelion
========================================
```

A focused, standalone **Cross-Site Scripting (XSS)** vulnerability scanner for
authorized web application security testing.

Vaelion-XSS injects payloads into every query-string parameter (and the URL
fragment) of a target URL, renders the resulting page in a real headless
Chrome browser, and confirms exploitation by catching the native JavaScript
dialog (`alert` / `confirm` / `prompt`) the payload triggers. Because it
verifies actual client-side execution rather than a naive string-reflection
match, it produces far fewer false positives than grep-based XSS checks.

## Overview

| Component | Details |
|---|---|
| Language | Python |
| Engine | Selenium + Headless Chrome |
| Detection | Real browser JavaScript execution |
| Payloads | 2600+ XSS payloads |
| Output | JSON / HTML / TXT reports |
| License | MIT |

## Roadmap

- [x] Reflected XSS detection
- [x] DOM XSS browser verification
- [x] Custom payload support
- [x] JSON/HTML reports

Future:
- [ ] Blind XSS support
- [ ] Burp Suite integration
- [ ] Better DOM sink analysis
- [ ] API mode

## Features

- **Real execution confirmation** — headless Chrome + Selenium, not a
  string-match heuristic
- **Multi-target scanning** — single `--url` or a `--file` of URLs
- **Threaded** — configurable worker pool (`--threads`) with a reusable
  browser-driver pool for throughput
- **Custom payloads** — bring your own payload file or a single ad-hoc
  payload via `--payload`
- **2,600+ curated XSS payloads** included out of the box
  (`payloads/xss.txt`)
- **Structured reports** — JSON, HTML, or plain text, auto-selected from the
  `--output` file extension
- **Verbose / debug mode** for troubleshooting scans
- **Colored terminal output** for fast visual triage
- **Clean exit codes** and error handling suitable for CI / automation

## Installation

Requires Python 3.9+ and Google Chrome installed on the host.

```bash
git clone https://github.com/pratikkhairnar160/Vaelion-XSS.git
cd Vaelion-XSS
pip install -r requirements.txt
```

`webdriver-manager` will automatically download a matching ChromeDriver on
first run — no manual driver setup required.

## Usage

Scan a single URL:

```bash
python3 vaelion_xss.py --url "https://target.tld/search?q=test"
```

Scan a list of URLs from a file, with more threads:

```bash
python3 vaelion_xss.py --file urls.txt --threads 10
```

Use a custom payload file and save an HTML report:

```bash
python3 vaelion_xss.py --url "https://target.tld/page?id=1" \
    --payload payloads/xss.txt \
    --output report.html
```

Test a single ad-hoc payload with verbose output:

```bash
python3 vaelion_xss.py --url "https://target.tld/page?id=1" \
    --payload "<script>alert(1)</script>" \
    --verbose
```

Save a JSON report for downstream tooling:

```bash
python3 vaelion_xss.py --file urls.txt --output findings.json
```

## Supported Options

| Flag | Short | Description | Default |
|---|---|---|---|
| `--url` | `-u` | Single target URL to scan | — |
| `--file` | `-f` | File containing one target URL per line | — |
| `--payload` | `-p` | Payload file path, or a single literal payload | `payloads/xss.txt` |
| `--threads` | `-t` | Number of concurrent worker threads | `5` |
| `--timeout` | | Seconds to wait for a JS dialog per request | `2.0` |
| `--output` | `-o` | Report file path (`.json`, `.html`, or `.txt`) | — |
| `--verbose` | `-v` | Enable verbose/debug logging | off |
| `--no-banner` | | Suppress the startup banner | off |
| `--version` | | Print version and exit | — |

`--url` and `--file` can be combined; targets are de-duplicated automatically.

## How Detection Works

1. Parse each target URL's query parameters (and fragment, if present).
2. For every parameter, generate a variant URL with the payload injected into
   that parameter only (all other parameters left untouched).
3. Load the variant in headless Chrome.
4. If a native JS dialog fires within `--timeout` seconds, the payload
   executed — the finding is recorded and printed immediately.
5. If no dialog fires, the variant is marked not vulnerable (shown only in
   `--verbose` mode).

This approach only flags payloads that actually run as JavaScript in a real
browser context, which is a meaningfully stronger signal than matching the
payload string back in the HTTP response body.

## Limitations

- Detects **reflected/DOM-based XSS that triggers a JS dialog**. It will not
  find stored XSS that requires a separate step to trigger, XSS that doesn't
  rely on `alert`/`confirm`/`prompt`-style payloads, or vulnerabilities behind
  authentication flows the scanner hasn't been given a session for.
  For DOM-based XSS the polyglot/dialog-based payloads in `payloads/xss.txt`
  still work since the sink executes in the rendered page.
- Requires Chrome/Chromium to be installed and reachable by
  `webdriver-manager`.
- Headless-browser scanning is inherently slower than pure HTTP scanning —
  tune `--threads` and `--timeout` to your target's tolerance and your own
  authorization scope.

## Legal Disclaimer

Vaelion-XSS is provided for **authorized security testing and educational
purposes only**. Only run this tool against systems you own or have explicit,
written permission to test.

Scanning systems without authorization is illegal in most jurisdictions
(e.g., under the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse
Act, and equivalent laws elsewhere) and may violate the target's Terms of
Service or bug bounty program rules even when technically reachable.

The author (**Vaelion**) assumes no liability and is not responsible for any
misuse or damage caused by this tool. Use it responsibly, stay in scope, and
follow the disclosure policy of any program you test under.

## Author

**Vaelion**

Security Researcher | Web Application Security | Bug Bounty | Application Security

## License

Released under the [MIT License](LICENSE).
