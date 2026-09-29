# Reflectra

**Context-Aware XSS Scanner**

Reflectra confirms Cross-Site Scripting by rendering candidate URLs in real headless Chrome and catching the native JavaScript dialog (`alert`/`confirm`/`prompt`) a payload triggers — not by pattern-matching a payload string back into the HTTP response. A string coming back in the response body is not a finding here; the browser actually executing it is.

## Quick start (the normal way to run this)

```bash
python3 reflectra.py
```

That's it. No flags to memorize. Reflectra asks a short series of questions — target URL, threads, auth, how many confirmed findings to stop after (default 5), whether to send blind payloads, and whether to deliver to Telegram — with a sensible default on every one (just press Enter). Answer, and the scan starts. A hacker-themed HTML report with clickable proof-of-concept links is **always** auto-saved into `./reports/`, named after the target, and delivered straight to your Telegram chat if you've opted in — even if you hit `Ctrl+C` mid-scan.

Everything below — the full CLI flag reference, CI usage, scripting — is for when you want more control than the wizard gives you. You don't need any of it to run a scan.

## 1. Project overview

Reflectra is the v2, professionally-restructured successor to **Vaelion-XSS**, a single-file XSS scanner built around Selenium + headless Chrome dialog confirmation. Reflectra keeps that detection core completely intact and adds an optimization layer around it: HTTP-based reflection probing, context-aware payload prioritization, DOM-sink static analysis, authenticated scanning, and blind/stored XSS injection support.

## 2. Why Reflectra exists

The original engine worked, but it was O(targets × payloads): every one of ~2,600 payloads was fired at every parameter regardless of whether that payload could ever fire in that parameter's actual reflection context. That's correct but wasteful — most of those browser requests were never going to succeed no matter how long you waited. Reflectra adds a cheap HTTP pre-check that tells you *where* a value lands before spending a browser request on it, so the same detection engine gets to more of what matters, faster — without ever having license to decide something "isn't worth checking."

## 3. Core capabilities

- Browser-confirmed reflected/DOM XSS via real `alert`/`confirm`/`prompt` dialog detection (the original engine, unmodified in behavior)
- Context-aware HTTP reflection probing that **prioritizes** payloads, never silently discards them
- Explicit, typed probe outcomes (`REFLECTED` / `AMBIGUOUS` / `NOT_REFLECTED` / `TIMEOUT` / `CONNECTION_ERROR` / `HTTP_ERROR`) so a network hiccup is never recorded as "not vulnerable"
- DOM-sink static analysis for payloads that don't fire a dialog, reported as unconfirmed leads
- Authenticated scanning via `--cookie` / `--header`
- Blind/stored XSS injection against an external collector you control
- JSON / HTML / TXT reporting with explicit finding kinds (`CONFIRMED_XSS`, `SINK_REACHABLE_LEAD`, `BLIND_INJECTION`, `ERROR`)
- Thread-pooled, driver-pooled scanning (one failed browser instance does not take down the pool)

## 4. Architecture

```
reflectra.py                CLI entrypoint — Target Manager / orchestration
reflectra/
    models.py                ProbeState, FindingKind, Finding, ReflectionResult
    urltools.py               Injection Point Discovery (query/fragment/synthetic params)
    context.py                Reflection classification + payload context tagging
    probe.py                  Reflection Probe (real HTTP requests, explicit failure states)
    planner.py                Payload Planner — fallback-safe task selection
    browser.py                *** ORIGINAL DETECTION CORE ***
                               DriverPool + dialog confirmation, carried over from
                               Vaelion-XSS almost line-for-line
    sinks.py                  DOM/Sink Analysis (unconfirmed leads only)
    blind.py                  Blind XSS payload templates
    report.py                 Result Aggregator + JSON/HTML/TXT Reporter (default style)
    hacker_report.py           Hacker-themed HTML report, findings grouped by bug class, table view, copy buttons
    banner.py                  ASCII banner, live colorized per-finding feed, results table
    telegram_notify.py         Telegram delivery of the final report (opt-in, credentials persisted)
    config.py                  Persistent local config (~/.reflectra/config.json) so Telegram creds are asked once
    naming.py                   Auto-generates report filenames into ./reports/, named after the target
    wizard.py                  Interactive one-click mode (no flags needed)
legacy_vaelion_xss.py         Original v1 script, unmodified, still runs standalone
payloads/xss.txt              ~2,600 curated XSS payloads (unchanged from v1)
tests/
    test_unit.py                     Pure-Python unit tests (24 tests)
    test_integration_probe.py        Real-HTTP integration tests against a local fixture server (10 tests)
    test_legacy_engine_compatibility.py   Browser-dependent compatibility checklist (Chrome-gated)
    fixtures/fixture_server.py       Deterministic local vulnerable test app
```

```text
target -> Injection Point Discovery -> Reflection Probe -> Context Classification
       -> Payload Planner -> ORIGINAL BROWSER CONFIRMATION ENGINE (browser.py)
       -> DOM/Sink Analysis -> Result Aggregator -> JSON / HTML / TXT Reporter
```

## 5. Detection methodology

A finding is only ever `CONFIRMED_XSS` if a real JS dialog fires in headless Chrome during navigation to the injected URL. That bar is unchanged from v1. Everything upstream of `browser.py` exists only to choose *which* payloads reach that bar first and *how many* — never whether a parameter gets tested at all.

## 6. Context-aware optimization (and its safety rules)

**Phase 1** sends one unique marker per injection point over plain HTTP and classifies where it landed: HTML text, double/single-quoted attribute, unquoted attribute, `<script>` block, URI attribute, or HTML comment.

**The optimization is prioritization, not filtering.** When context is confidently detected (`ProbeState.REFLECTED`), matching payloads are moved to the front of the list — the rest of the ~2,600 payloads still run after them unless you explicitly set `--max-payloads-per-point` to a smaller number. By default (`--max-payloads-per-point 0`), **nothing is dropped**, full v1-equivalent coverage is preserved, and you only get faster time-to-first-finding, not reduced coverage.

**Every non-`REFLECTED` outcome falls back to full coverage automatically:**

| Probe outcome | Planner behavior |
|---|---|
| `REFLECTED` | Prioritize matching payloads first, keep the rest (subject to explicit cap) |
| `AMBIGUOUS` | Run the full payload list, unfiltered |
| `NOT_REFLECTED` | Sample a slice (pure client-side DOM XSS isn't visible to a server-side probe) |
| `TIMEOUT` | **Full payload list, unfiltered** — a probe failure is not evidence |
| `CONNECTION_ERROR` | **Full payload list, unfiltered** |
| `HTTP_ERROR` | **Full payload list, unfiltered** |

`--no-context-filter` disables phase 1 entirely and reproduces v1's exhaustive brute-force behavior exactly, through the same fallback code path used for real probe failures — so there's only one "full coverage" implementation to keep correct, not two.

## 7. Browser-confirmed XSS

`browser.py`'s `BrowserConfirmationEngine.confirm_one()` is the original v1 `_check_injection` routine: acquire a pooled driver, navigate, wait up to `--timeout` seconds for `EC.alert_is_present()`, accept and record on success, handle `UnexpectedAlertPresentException` as a hit too, treat `WebDriverException` as a per-payload error (not "not vulnerable"), release the driver. Driver creation failures (no Chrome binary, no network to fetch chromedriver, etc.) are also caught and recorded as `ERROR` findings — a systemic failure is never silently invisible in the summary.

## 8. DOM sink leads

`sinks.py` performs a heuristic, non-taint-tracking check: after a payload fails to fire a dialog, the rendered DOM is scanned for the payload's raw text sitting inside a call to `innerHTML`, `outerHTML`, `document.write`, `eval`, `insertAdjacentHTML`, `setTimeout`, `setInterval`, or similar. These are reported as `SINK_REACHABLE_LEAD` and are **never** equivalent to `CONFIRMED_XSS` in code, reports, or the CLI summary — they exist because CSP, missing user interaction, or a conditional sink can suppress the dialog while the underlying primitive is still real and worth a manual look.

## 9. Authentication

`--cookie "session=abc; role=user"` and repeatable `--header "Name: value"` are applied to both the phase-1 `requests.Session` and the phase-2 browser driver (via `driver.add_cookie` after an initial navigation to the target's origin), so authenticated coverage is consistent across both phases. Secret values are never printed, even in `--verbose` mode — only that a cookie/header was set and its length.

## 10. Blind XSS

`--blind-url <collector>` injects a small set of exfiltration payloads (`<script src>`, `fetch`-based cookie/DOM exfil) into every parameter of every target, fire-and-forget over plain HTTP. Reflectra does **not** host a collector — point it at Burp Collaborator, Interactsh, xss.report, or a self-hosted XSS Hunter Express instance you already control. Reports label these `BLIND_INJECTION`, explicitly distinct from `CONFIRMED_XSS`: injection is not confirmation. Confirmation happens on your external collector, out of band.

## 11. Installation

Requires Python 3.9+ and Google Chrome/Chromium installed and reachable by `webdriver-manager`.

```bash
git clone https://github.com/pratik-khairnar-sec/Reflectra.git
cd Reflectra
pip install -r requirements.txt
```

## 12. Kali/Linux installation (`.venv`)

```bash
sudo apt update && sudo apt install -y chromium chromium-driver python3-venv
git clone https://github.com/pratik-khairnar-sec/Reflectra.git
cd Reflectra
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 reflectra.py --version
```

## 13. Windows installation

```powershell
git clone https://github.com/pratik-khairnar-sec/Reflectra.git
cd Reflectra
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python reflectra.py --version
```

Ensure Google Chrome is installed; `webdriver-manager` fetches a matching chromedriver automatically on first run (requires outbound network access to `googlechromelabs.github.io`).

## 14. Usage examples

```bash
# One-click interactive mode -- no flags to remember. Asks target, threads,
# auth, stop-on-first, blind XSS, output path, and Telegram (once ever).
python3 reflectra.py

# Basic scan — full original payload coverage, context-prioritized ordering
python3 reflectra.py --url "https://target.tld/search?q=test"

# Multiple targets, more threads, HTML report
python3 reflectra.py --file urls.txt --threads 10 --output report.html

# Authenticated scan
python3 reflectra.py --url "https://target.tld/dashboard?id=1" \
    --cookie "session=abc123; role=user" --header "X-CSRF-Token: xyz"

# Reproduce v1's exact exhaustive brute-force behavior
python3 reflectra.py --url "https://target.tld/page?id=1" --no-context-filter

# Explicitly cap payloads per point for a faster, less exhaustive pass
python3 reflectra.py --url "https://target.tld/page?id=1" --max-payloads-per-point 150

# Blind XSS against a collector you control
python3 reflectra.py --file urls.txt --blind-url "https://your-id.xss.report" --blind-only

# JSON report for downstream tooling / CI
python3 reflectra.py --file urls.txt --output findings.json

# Stop as soon as the first XSS is confirmed -- cancels remaining queued tasks
python3 reflectra.py --url "https://target.tld/page?id=1" --max-confirmed 5
```

## 15. CLI reference

```
target selection:
  -u, --url URL              Single target URL to scan
  -f, --file FILE             File of target URLs, one per line

scan options:
  -p, --payload PATH           Payload file or a single literal payload (default: payloads/xss.txt)
  -t, --threads N               Concurrent browser worker threads (default: 5)
  --timeout SECONDS             Seconds to wait for a JS dialog (default: 2.0)
  --max-payloads-per-point N     Cap payloads per point after prioritization (0 = no cap, default)
  --no-context-filter            Skip phase 1, run full original payload list against every point
  --no-sink-probe                 Disable DOM-sink static analysis
  --skip-unreflected              Don't sample NOT_REFLECTED points at all
  --max-confirmed N                Stop scanning after N confirmed XSS findings (default: unbounded)
  --stop-on-first-confirmed        Shorthand for --max-confirmed 1

authentication:
  --cookie "k=v; k2=v2"          Cookie header string
  --header "Name: value"          Extra header, repeatable
  --insecure                       Disable TLS certificate verification

blind / stored XSS:
  --blind-url URL                  External OOB collector URL
  --blind-only                      Only run blind injection, skip browser confirmation

output:
  -o, --output PATH                Report file (.json / .html / .txt). If omitted, auto-saved as HTML into
                                     ./reports/, named after the target + timestamp
  --report-style {default,hacker}   HTML report visual style (default: hacker; only applies to .html output)
  --plain                          Disable ANSI colors / ASCII banner in terminal output
  -v, --verbose
  --no-banner
  --version

telegram delivery:
  --telegram-token TOKEN            Telegram bot token (from @BotFather)
  --telegram-chat-id CHAT_ID        Telegram chat/channel ID to deliver the final report to
```

`python3 reflectra.py --help` is the source of truth; every flag above was verified against actual `argparse` output (see Testing).

## 15b. Terminal experience

Reflectra prints a full-width ASCII banner and a colorized, ANSI-formatted live summary on every run (`reflectra/banner.py`). As each finding comes in during the scan, a live-colored line prints immediately — green for confirmed, amber for sink leads, cyan for blind injections, red for errors — so you can watch results arrive in real time instead of waiting for the final report. At the end, a colorized results table lists every finding with its kind, context, and URL before the summary stats. Color is auto-detected: it disables itself automatically when output isn't a real terminal (piped to a file, redirected in CI) or when `NO_COLOR` is set, and can be force-disabled with `--plain`. This is purely a presentation layer — it reads `engine.findings` and `plan_stats` after each finding is recorded, it does not participate in detection, probing, or planning.

## 15c. Hacker-themed HTML reporting

Pass `-o report.html` (the default `--report-style` is `hacker`) to generate a dark, CRT/terminal-styled report (`reflectra/hacker_report.py`) with findings automatically grouped by bug class — Script-Context XSS, HTML-Context XSS, Attribute-Context XSS, URI-Context XSS, DOM/Client-Side XSS, Blind/Stored XSS, Full-Coverage Fallback, and Scan Errors — instead of one flat table. Every finding URL is a clickable link that opens in a new tab (for manual proof-of-concept verification), confirmed findings have a one-click "copy payload" button, and a toggle switches between the grouped card view and a plain table view of every finding — same data, pick whichever layout suits sending straight to a client or program. Use `--report-style default` for the plain GitHub-friendly HTML report instead. Both are generated from the exact same `engine.findings`/`plan_stats` data; only the rendering differs.

## 15d. One-click wizard mode

Run `python3 reflectra.py` with no arguments — this is the primary, intended way to use Reflectra — and it walks you through a numbered, colorized 6-step setup instead of requiring you to remember flags: target URL, scan speed, authentication, stop condition (how many confirmed findings to stop after, default 5), blind XSS, and Telegram delivery. Every question has a sensible default — just press Enter. The report path is never asked — it's always auto-saved into `./reports/`, named after the target. Run `--wizard` explicitly to force this mode even alongside other flags.

## 15e. Stop after N confirmed findings

`--max-confirmed N` (or a number in the wizard, default `5`) stops the scan once N `CONFIRMED_XSS` findings have been recorded — remaining queued browser tasks are cancelled rather than left to run to completion. `--stop-on-first-confirmed` is shorthand for `--max-confirmed 1`. This is opt-in and unbounded by default when using the CLI flags directly; every existing test and the default CLI behavior are unaffected by it. The wizard defaults to `5` since that's a practical balance for a quick triage pass — enough findings to know the target is vulnerable without scanning every remaining parameter once the point is already proven.

## 15f. Reports are always saved

Every scan produces a report — there is no "no report" case. If you don't pass `-o`, Reflectra auto-saves a hacker-themed HTML report into `./reports/`, named after the target and a timestamp, e.g. `reports/reflectra_target-tld_20260929-141501.html`. This happens on normal completion, on hitting the `--max-confirmed` threshold, and on `Ctrl+C` — whatever was found gets written and (if Telegram is configured) delivered.

## 15f. Telegram delivery

```bash
python3 reflectra.py --url "https://target.tld/search?q=test" \
    --telegram-token "123456:ABC-DEF..." \
    --telegram-chat-id "987654321" \
    -o report.html
```

The first time you supply `--telegram-token`/`--telegram-chat-id` (or answer "yes" in the wizard) and a message successfully sends, Reflectra saves them to `~/.reflectra/config.json` (file permissions `0600`, never committed — it's in `.gitignore`) so you are **never asked again**: every future run — including plain `python3 reflectra.py --url ...` with no Telegram flags at all — automatically delivers the report to that saved chat. Run `--forget-telegram` at any time to delete the saved credentials.

At the end of a scan — and on `Ctrl+C`, since results gathered so far are always delivered before exiting — Reflectra sends a short HTML-formatted summary message to that chat, and — if `-o` was also given — attaches the full report file as a document. Setup: message `@BotFather` on Telegram to create a bot and get a token, message your new bot once, then `GET https://api.telegram.org/bot<token>/getUpdates` to find your `chat_id`. Token and chat ID are never printed in full, even in `--verbose` mode — only their length is logged. This feature is entirely opt-in and additive (`reflectra/telegram_notify.py`, `reflectra/config.py`); nothing else in the tool depends on or is aware of it.

## 16. Output examples

Terminal summary (abbreviated):

```
------------------------------------------------------------
Scan finished.
  Injection points probed : 4
    reflected (context OK) : 3
    ambiguous               : 0
    not reflected           : 1
    probe failed (fallback) : 0
  Browser tasks planned    : 612
  Confirmed XSS            : 1
  Sink-reachable leads     : 2  (unconfirmed -- manual review)
  Blind injections sent    : 0  (unconfirmed -- check external collector)
  Errors                   : 0  (NOT the same as 'not vulnerable')
  Browser requests sent    : 612
  Time taken               : 41.2s
------------------------------------------------------------
```

JSON/HTML/TXT reports carry the same `plan_stats` breakdown plus per-finding detail (`kind`, `target_url`, `payload`, `injected_url`, `context`, `dialog_text`/`detail`, `timestamp`).

## 17. Testing

**This section states exactly what was run, in the environment this v2 upgrade was built in, and nothing more.**

Executed and passing:
- `python3 -m compileall .` — clean
- `python3 reflectra.py --help` / `--version` — verified, all documented flags present in real `argparse` output
- `tests/test_unit.py` — **24/24 passed.** Pure-Python: URL/parameter handling, reflection classification, payload tagging, and — critically — the planner's fallback behavior: explicit assertions that `TIMEOUT`/`CONNECTION_ERROR`/`HTTP_ERROR`/`AMBIGUOUS` probe outcomes always produce the **full, uncapped payload list** (tested at v1-parity scale, 2,605 payloads), never a reduced one.
- `tests/test_integration_probe.py` — **10/10 passed**, against a real local HTTP server (`tests/fixtures/fixture_server.py`), real `requests` calls over real sockets — not mocked. Covers HTML/attribute/script-context reflection, a true `NOT_REFLECTED` case, multi-parameter isolation, a genuine `CONNECTION_ERROR` against a dead port, a genuine `TIMEOUT` against a non-routable address, cookie/header auth wiring, and the fallback path flowing correctly from a real probe failure into the planner.
- Live CLI dry-runs against the local fixture server (`--url`, `--no-context-filter`, `--blind-url`) — probe → planner wiring confirmed correct in each mode.

Written but **not executed against a real browser** (Chrome/Chromium could not be installed in the development sandbox — no usable package, no network path to a real installer):
- `tests/test_legacy_engine_compatibility.py` — 10 test cases covering the exact checklist this upgrade was required to satisfy (alert/confirm/prompt recognition, one worker's failure not affecting others, driver cleanup, threaded stability, payload-semantics round-tripping). Gated with `@pytest.mark.skipif` on `shutil.which("chrome"/"chromium")`; **verified in this environment to skip cleanly (7 skipped, 3 non-browser assertions passed)** rather than fake a pass. **Run these yourself** on a machine with Chrome/Chromium installed before relying on the browser-confirmation path:
  ```bash
  pip install pytest
  python3 -m pytest tests/ -v
  ```

Do not read "unit tested" anywhere in this document as "browser integration tested." They are reported separately on purpose.

**Presentation-layer additions** (`hacker_report.py`, `banner.py`, `telegram_notify.py`) were verified directly against synthetic `Finding`/`PlanStats` objects covering every `FindingKind` (confirmed, sink-lead, blind, error) — output inspected manually for correct HTML-escaping, correct bug-class grouping, and correct color/badge mapping. They consume already-produced results and were not run against a live Telegram bot in this environment (no bot token available here); test with a real token/chat-id before relying on it for delivery.

## 18. Limitations

- **Not taint analysis.** Sink leads check whether payload text sits inside a dangerous sink call — they don't trace data flow. Manual confirmation required before reporting anywhere.
- **Context classification is heuristic**, not a full parser. Deliberately conservative (falls back to full coverage on ambiguity), but can still misclassify unusual markup — this is why filtering, not the planner's discard path, is what's disabled by uncertainty.
- **Single-request scanner.** No multi-step trigger simulation; stored XSS requiring a separate viewing action isn't self-confirmed — pair `--blind-url` with your own collector for that class.
- **Browser confirmation requires Chrome/Chromium reachable by webdriver-manager**, including outbound network access to fetch a matching chromedriver on first run.
- **No CSP-awareness yet** — a sink-reachable lead may simply be CSP-blocked; the tool doesn't yet tell you which.
- **No WAF/rate-limit adaptive backoff yet.**

## 19. Roadmap

- CSP-aware payload filtering (skip payloads a target's CSP will provably block)
- WAF/rate-limit detection with adaptive backoff
- Burp Suite extension / API mode for pipeline integration
- Expanded DOM-sink coverage and confidence scoring
- Optional bundled offline chromedriver cache for network-restricted environments

## 20. Responsible use / legal

Reflectra is provided for authorized security testing and educational purposes only. Only run this tool against systems you own or have explicit, written permission to test — including explicit scope for blind/stored XSS and out-of-band collaborator use, which many programs restrict separately from reflected XSS.

Scanning systems without authorization is illegal in most jurisdictions (e.g., the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalent laws elsewhere) and may violate a target's Terms of Service or bug bounty program rules even when technically reachable. The author assumes no liability for misuse. Stay in scope, follow the disclosure policy of any program you test under.

## 21. Author

**Pratik Khairnar**
GitHub: [https://github.com/pratik-khairnar-sec](https://github.com/pratik-khairnar-sec)
Security Researcher — Web Application Security, Bug Bounty, XSS Research

## 22. License

MIT — see [LICENSE](LICENSE).
