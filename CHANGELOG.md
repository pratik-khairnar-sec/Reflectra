# Changelog

## v2.1.0 — Reflectra (UX release: wizard, Telegram, auto-reporting)

Builds on v2.0.0's architecture without touching the detection core (`browser.py`'s `confirm_one`/`DriverPool` logic is unchanged from v2.0.0). This release is about making the tool fast to pick up and demo-ready, not about changing what "confirmed" means.

### Added
- `reflectra/wizard.py`: interactive one-click mode — run `python3 reflectra.py` with no arguments and get a numbered, colorized 6-step prompt flow (target, speed, auth, stop condition, blind XSS, Telegram) instead of needing to remember CLI flags. Every question has a sensible default.
- `reflectra/config.py`: persistent local Telegram credential storage (`~/.reflectra/config.json`, `chmod 600`) — token/chat ID are asked once, ever; every future run (wizard or plain CLI) auto-delivers without re-asking. `--forget-telegram` clears it.
- `reflectra/naming.py`: reports are now **always** saved — if `-o` isn't given, an HTML report auto-saves into `./reports/`, named after the target and a timestamp (e.g. `reports/reflectra_target-tld_20260929-141501.html`).
- `--max-confirmed N`: stop the scan after N confirmed XSS findings (cancels remaining queued browser tasks, not just future ones not yet picked up). Wizard default is `5`. `--stop-on-first-confirmed` kept as shorthand for `N=1`.
- `reflectra/banner.py`: live, per-finding colorized terminal feed as results come in (green=confirmed, amber=sink-lead, cyan=blind, red=error), plus a colorized results table before the final summary.
- `reflectra/hacker_report.py`: every finding URL is now a real `target="_blank"` link for manual proof-of-concept verification, confirmed findings have a one-click "copy payload" button, and a card/table view toggle switches between the grouped-by-bug-class layout and a flat table — same data, either layout.
- On `Ctrl+C`, results gathered so far are always written to a report and delivered to Telegram (if configured) before exiting, same as a normal completion.

### Changed
- `BrowserConfirmationEngine.__init__` gained `max_confirmed: Optional[int]` (general form) alongside the existing `stop_on_first_confirmed: bool` (now an alias for `max_confirmed=1`) and `on_finding: Optional[callable]` (live UI callback). All three are additive, default-off/`None`, and do not change behavior for any existing caller that doesn't set them.
- `deliver_results()` in `reflectra.py` no longer has a "no report" branch — a report path is always resolved (explicit `-o`, or auto-named) before rendering, so Telegram delivery (when configured) always has a file to attach.

### Testing added this release
- `tests/test_unit.py` grew from 24 to 35 tests: stop-on-first/`max_confirmed` threshold behavior (confirms it does *not* stop early at 1-4 confirmed when the threshold is 5), `on_finding` callback invocation and exception-safety, and `reflectra/naming.py` path generation (directory creation, slug sanitization, multi-target labels).
- Wizard flow and `deliver_results()` auto-naming verified end-to-end with simulated input and synthetic findings — confirmed the report file is actually written with the target name embedded, not just that a path string is returned.

### Known limitations (unchanged from v2.0.0, still honest)
- The actual browser-confirmation path (`browser.py`) has still not been executed against a real Chrome instance in the environment this was built in — no Chrome/Chromium binary available there. Logic is unchanged from the v2.0.0 code that was structurally reviewed against the original working v1 engine; run `tests/test_legacy_engine_compatibility.py` yourself on a machine with Chrome installed before treating it as verified.
- No CSP-awareness, no WAF/rate-limit backoff (see README Roadmap).
- Context classifier is heuristic; `AMBIGUOUS`/misclassification always falls back to full coverage rather than being resolved more precisely.

## v2.0.0 — Reflectra (initial architecture)

Renamed from Vaelion-XSS, restructured from one ~600-line script into a package. `reflectra/browser.py` is the preserved v1 detection core — not reimplemented — with every other module built additively around it.

### Added
- `reflectra/browser.py`: original v1 `DriverPool` and `_check_injection` confirmation logic, restructured into `BrowserConfirmationEngine`, preserved as the detection core — not reimplemented.
- `reflectra/models.py`: explicit `ProbeState` enum (`REFLECTED`/`AMBIGUOUS`/`NOT_REFLECTED`/`TIMEOUT`/`CONNECTION_ERROR`/`HTTP_ERROR`) and `FindingKind` enum (`CONFIRMED_XSS`/`SINK_REACHABLE_LEAD`/`BLIND_INJECTION`/`ERROR`/`INCONCLUSIVE`).
- `reflectra/probe.py`: real-HTTP phase-1 reflection probing with explicit failure-state classification (never conflates a timeout with "not reflected").
- `reflectra/planner.py`: fallback-safe payload selection — prioritizes on confident context, but only ever *reorders*; only an explicit `--max-payloads-per-point` cap can reduce coverage, and probe failures (`TIMEOUT`/`CONNECTION_ERROR`/`HTTP_ERROR`/`AMBIGUOUS`) always yield full, uncapped coverage.
- `reflectra/sinks.py`: DOM-sink static analysis, reported as `SINK_REACHABLE_LEAD` (unconfirmed), never conflated with `CONFIRMED_XSS`.
- `reflectra/blind.py`: blind/stored XSS payload injection against an external, user-supplied OOB collector.
- `--cookie` / `--header` authenticated scanning, applied consistently to both the probe session and the browser driver; secret values masked in verbose logs.
- `--no-context-filter`, `--max-payloads-per-point`, `--skip-unreflected`, `--blind-url`, `--blind-only`, `--insecure` CLI flags — every one verified working against real `argparse --help` output.
- Test suite: `tests/test_unit.py` (24 tests), `tests/test_integration_probe.py` (10 tests, real local HTTP server), `tests/test_legacy_engine_compatibility.py` (10-case browser compatibility checklist, Chrome-gated).
- `tests/fixtures/fixture_server.py`: dependent-free local vulnerable test app with deterministic HTML/attribute/script/DOM-only/escaped reflection cases, for testing without relying on a third-party target.

### Changed
- Project renamed Vaelion-XSS → Reflectra; restructured from one ~600-line script into a package. `browser.py` is the preserved detection core; every other module is additive orchestration around it.
- Report schema now distinguishes `CONFIRMED_XSS` from `SINK_REACHABLE_LEAD` from `BLIND_INJECTION` from `ERROR` — previously v1 only had implicit "vulnerable" vs. "not vulnerable, or errored" states, with errors under-visible in the summary.

### Improved
- Default behavior favors coverage over aggression: `--max-payloads-per-point` now defaults to `0` (no cap) rather than the earlier draft's default of 150 — every payload still runs, context detection only changes ordering unless the user explicitly opts into a smaller cap.
- Probe failures (network timeout, connection refused, 5xx) are structurally incapable of being read as "not reflected" — they route through a dedicated `FALLBACK_STATES` set in `planner.py` that always yields full payload coverage for that point.

### Fixed
- **Driver-acquisition failures now produce a `FindingKind.ERROR`** (previously: a failure inside `DriverPool.acquire()` — e.g. no Chrome binary, no network to fetch chromedriver — only incremented an internal counter with no corresponding `Finding`, so the scan summary could show `Errors: 0` / `Confirmed: 0` even when the browser layer never actually ran. Caught during this project's own live CLI dry-run testing; fixed in `browser.py::confirm_one` and reflected in `report.py`'s summary line, which now takes `max(finding_count, stats.total_errors)` as an additional safety net.
- Earlier draft's `context.py::select_payloads()` *filtered* non-matching payloads outright on confident context detection. Replaced with `planner.py::select_for_point()`, which *reorders* and only truncates via an explicit user-controlled cap — this was the actual architectural regression flagged in review, now corrected.

### Known limitations
- Browser-confirmation path (`browser.py`) is unit/structurally reviewed and unchanged in logic from the tested-working v1 engine, but has **not** been executed end-to-end against a real Chrome instance in this development environment. Treat as unverified until you run `tests/test_legacy_engine_compatibility.py` yourself.
- No CSP-awareness, no WAF/rate-limit backoff (see README Roadmap).
- Context classifier is heuristic; `AMBIGUOUS`/misclassification always falls back to full coverage rather than being resolved more precisely.

## v1.0.0 — Vaelion-XSS (original)

Single-file scanner (`vaelion_xss.py`, preserved unmodified as `legacy_vaelion_xss.py`):
- Selenium + headless Chrome, `DriverPool` for driver reuse across threads
- Injects every payload into every query/fragment parameter of every target (exhaustive, O(targets × payloads))
- Confirms via native JS dialog (`alert`/`confirm`/`prompt`) detection
- JSON / HTML / TXT reports
- ~2,600 curated payloads (`payloads/xss.txt`)
- Threaded via `ThreadPoolExecutor`, `--threads` configurable
