# Reflectra — User Guide

This guide covers everything from first install to running Reflectra as part of a real bug bounty workflow, in depth. For a quick architectural overview, see README.md; this document is the "how do I actually use it" companion.

---

## 1. Requirements

- Python 3.9 or newer
- Google Chrome or Chromium, installed and on your `PATH` (or discoverable by `webdriver-manager`)
- Outbound internet access on first run, so `webdriver-manager` can download a matching `chromedriver` build
- (Optional) A Telegram bot token and chat ID, if you want scan results delivered to Telegram

---

## 2. Installation

### 2.1 Linux / Kali (recommended: virtual environment)

```bash
sudo apt update && sudo apt install -y chromium chromium-driver python3-venv git
git clone https://github.com/pratik-khairnar-sec/Reflectra.git
cd Reflectra
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 reflectra.py --version
```

### 2.2 Windows

```powershell
git clone https://github.com/pratik-khairnar-sec/Reflectra.git
cd Reflectra
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python reflectra.py --version
```

Install Google Chrome from google.com/chrome if it isn't already present. `webdriver-manager` handles the matching `chromedriver` automatically.

### 2.3 macOS

```bash
brew install --cask google-chrome
git clone https://github.com/pratik-khairnar-sec/Reflectra.git
cd Reflectra
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 reflectra.py --version
```

If `--version` prints a version string, the install is good.

---

## 3. Your first scan

**The easy way — just run it:**

```bash
python3 reflectra.py
```

Answer the prompts (target URL, threads, auth, stop-after-N-confirmed, Telegram) — every question has a default, so pressing Enter through all of them gives you a sensible scan. A hacker-themed report is always auto-saved into `./reports/`, named after the target. This is the recommended way to run Reflectra day to day.

**The scripted/CI way**, if you want full control without prompts:

```bash
python3 reflectra.py --url "https://target.tld/search?q=test"
```

What happens, in order, either way:

1. **Banner** prints (disable with `--no-banner` or `--plain` for CI logs).
2. **Target loading** — `--url` and/or `--file` are read and de-duplicated.
3. **Phase 1 — reflection probe.** A plain HTTP request per parameter, using a unique marker, to determine where (if anywhere) it reflects.
4. **Payload planner.** Builds the task list. Confidently-classified reflections get prioritized payload ordering; anything uncertain (timeout, connection error, ambiguous context, HTTP 5xx) automatically falls back to the full, uncapped payload list — this is a deliberate safety rule, not an oversight (see README §6).
5. **Phase 2 — browser confirmation.** The original, unmodified detection engine: headless Chrome navigates to each candidate URL and waits for a JS dialog.
6. **Sink probing.** For payloads that don't fire a dialog, a quick DOM check flags whether the payload landed inside a dangerous sink (unconfirmed lead, not a finding).
7. **Report + delivery.** Terminal summary always prints; `-o` writes a file; `--telegram-token`/`--telegram-chat-id` sends it to Telegram too.

---

## 4. Scanning multiple targets

```bash
cat > urls.txt << EOF
https://target.tld/search?q=1
https://target.tld/profile?id=1&tab=info
https://sub.target.tld/app#/route?x=1
EOF

python3 reflectra.py --file urls.txt --threads 10 -o report.html
```

`--url` and `--file` can be combined; targets are de-duplicated automatically. Increase `--threads` for faster browser-phase throughput — bounded by your machine's ability to run that many headless Chrome instances at once (start at 5-10, watch memory).

---

## 5. Coverage vs. speed — the knobs that matter

Reflectra defaults to **full coverage**: every payload still gets tried at a reflecting point, just prioritized by context so the most likely ones run first. If you want a faster, less exhaustive pass instead:

```bash
# Cap at 150 payloads per confidently-classified point (uncertain points still get the full list)
python3 reflectra.py --url "..." --max-payloads-per-point 150

# Skip phase 1 entirely and brute-force everything, exactly like the original v1 engine
python3 reflectra.py --url "..." --no-context-filter

# Don't even sample parameters that didn't reflect over HTTP (faster; may miss pure client-side DOM XSS)
python3 reflectra.py --url "..." --skip-unreflected
```

**Rule of thumb:** for a first-pass triage across many URLs, use `--max-payloads-per-point 150-300`. For a focused, "I need to be sure" pass on one or two high-value parameters, leave the cap at `0` (default) or use `--no-context-filter`.

---

## 6. Authenticated scanning

Most real reachable XSS in current bug bounty programs sits behind auth. Reflectra applies cookies/headers to both the reflection probe and the browser confirmation phase:

```bash
python3 reflectra.py --url "https://target.tld/dashboard?id=1" \
    --cookie "session=eyJhbGciOi...; csrf=abc123" \
    --header "X-Requested-With: XMLHttpRequest"
```

Values are masked in `--verbose` logs (only their length is shown) — they are never printed in full, and never written into report files as-is (reports contain the injected URLs and payloads, not your session cookie).

Use `--insecure` if the target's TLS certificate isn't trusted (self-signed staging environments, internal targets).

---

## 7. Blind / stored XSS

Reflectra does not run its own out-of-band collector — point it at one you already control:

```bash
python3 reflectra.py --file urls.txt \
    --blind-url "https://your-id.xss.report" \
    --blind-only
```

- `--blind-only` skips live browser confirmation entirely and only fires the blind payload set.
- Without `--blind-only`, blind payloads are injected first, then the normal probe/plan/confirm flow runs afterward.
- Blind injections are reported as `BLIND_INJECTION` — this proves the payload was **sent**, not that it fired. Check your collector for actual confirmation.

**Check program scope first.** Blind XSS testing and OOB collaborator use are often scoped separately from reflected XSS in bug bounty policies.

---

## 8. Reading the report

### Terminal summary
Always printed, color-coded (green = confirmed, amber = sink lead, cyan = blind, red = error). `--plain` disables color for clean CI/log output.

### HTML report (`-o report.html`)
Default style is `hacker` — a dark, CRT-terminal-themed report with findings grouped by bug class (Script-Context XSS, HTML-Context XSS, Attribute-Context XSS, URI-Context XSS, DOM/Client-Side XSS, Blind/Stored XSS, Full-Coverage Fallback, Scan Errors). This is the one worth screenshotting for a writeup or portfolio piece. Use `--report-style default` for a plainer table-style report instead.

### JSON report (`-o findings.json`)
Structured, includes `plan_stats` and every `Finding` with its `kind`, `target_url`, `payload`, `injected_url`, `context`, `dialog_text`/`detail`, and `timestamp`. Feed this into other tooling or CI pipelines.

### What each finding kind means

| Kind | Meaning |
|---|---|
| `CONFIRMED_XSS` | A real JS dialog fired in headless Chrome. This is the only category you should report to a program as-is. |
| `SINK_REACHABLE_LEAD` | Payload text landed inside a dangerous DOM sink call, but no dialog fired (often CSP, missing interaction, or a conditional sink). Needs manual confirmation before you report it anywhere. |
| `BLIND_INJECTION` | Payload was sent to a stored/async sink. Confirmation happens on your external collector, not here. |
| `ERROR` | The payload could not be tested (network/browser failure). **Not** "not vulnerable" — if this count is high, something's wrong with your environment/target reachability, not necessarily the target's security. |

---

## 9. Telegram delivery — full setup

1. Open Telegram, message **@BotFather**, send `/newbot`, follow the prompts. You'll get a token like `123456789:AAF...`.
2. Send any message to your new bot (or add it to a group/channel and send a message there).
3. In a browser, visit `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` and find `"chat":{"id": ...}` in the JSON — that number is your `chat_id`.
4. Run Reflectra with both values:

```bash
python3 reflectra.py --url "https://target.tld/search?q=test" \
    --telegram-token "123456789:AAF..." \
    --telegram-chat-id "987654321" \
    -o report.html
```

You'll get a short summary message immediately, followed by the full report file as an attached document. If delivery fails, Reflectra logs a warning and continues — it never blocks or fails your scan over a notification issue.

---

## 10. Automated / CI usage

```bash
python3 reflectra.py --file targets.txt --plain --no-banner \
    -o findings.json --max-payloads-per-point 200 \
    --telegram-token "$TG_TOKEN" --telegram-chat-id "$TG_CHAT" \
    || echo "scan exited non-zero, check logs"
```

`--plain` and `--no-banner` keep output clean for log capture. Exit code `0` on a normal completed scan, `130` on interrupt, `1` on a fatal error before any results could be produced.

---

## 11. Testing your own setup before relying on it

Before running Reflectra against anything that matters, confirm your environment actually works end to end:

```bash
pip install pytest
python3 -m pytest tests/ -v
```

- If you have Chrome/Chromium installed, `tests/test_legacy_engine_compatibility.py` should run (not skip) and pass — this exercises the actual browser-confirmation path (alert/confirm/prompt detection, driver cleanup, threaded stability) against a local fixture app (`tests/fixtures/fixture_server.py`), no external target needed.
- If those tests skip with a "No Chrome/Chromium binary found" message, install Chrome/Chromium first — the browser-confirmation path has not been verified without it.

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Errors: N` high, `Confirmed: 0` on everything | Chrome/chromedriver not reachable | Check `google-chrome --version` works; check outbound network access for `webdriver-manager`'s first-run download |
| Scan hangs for a long time before anything happens | `webdriver-manager` trying (and failing) to reach the internet | Ensure the machine running Reflectra has outbound HTTPS access, or pre-cache a chromedriver manually |
| Telegram message never arrives | Wrong token/chat_id, or bot never messaged first | Re-check `getUpdates`, confirm the bot was messaged at least once |
| Report file didn't get written | Scan crashed before completion, or bad output path/extension | Use `-v` for verbose logs; confirm the output directory exists and is writable |
| False negative suspected on a param you know is vulnerable | Try `--no-context-filter` to rule out prioritization ordering, and check `--timeout` is long enough for a slow target |

---

## 13. Legal reminder

Only run Reflectra against systems you own or have explicit written authorization to test. See README §20 for the full statement.
