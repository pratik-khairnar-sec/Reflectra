#!/usr/bin/env python3
"""
Reflectra
=========
Context-Aware XSS Scanner.

Detection core (browser.py) is the original Reflectra-XSS Selenium/Chrome
engine, preserved. Everything else in this file is orchestration around
that core: target/payload loading, the phase-1 reflection probe, the
fallback-safe payload planner, and reporting.

Author: Pratik Khairnar
GitHub: https://github.com/pratik-khairnar-sec
License: MIT — see LICENSE

For authorized security testing and bug bounty use only. See README.md.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from reflectra.blind import build_blind_payloads
from reflectra.browser import VERSION, BrowserConfirmationEngine
from reflectra.engine import brute_force_probe_results
from reflectra.planner import plan_tasks
from reflectra.probe import build_session, probe_target
from reflectra.report import print_summary, write_report
from reflectra.urltools import injection_points
from reflectra.banner import print_banner, print_summary_block, print_finding_live, print_results_table
from reflectra.hacker_report import write_hacker_report
from reflectra import telegram_notify
from reflectra import config as cfgmod
from reflectra import naming
from reflectra.wizard import run_wizard

DEFAULT_PAYLOAD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads", "xss.txt")

BANNER = f"""========================================
          Reflectra v{VERSION}
   Context-Aware XSS Scanner
========================================"""


def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("reflectra")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = "%(asctime)s [%(levelname)s] %(message)s" if verbose else "%(message)s"
        handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
        logger.addHandler(handler)
    logging.getLogger("WDM").setLevel(logging.ERROR if not verbose else logging.INFO)
    logging.getLogger("selenium").setLevel(logging.ERROR if not verbose else logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.ERROR if not verbose else logging.WARNING)
    return logger


def load_payloads(path: str, logger: logging.Logger) -> list[str]:
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            payloads = [
                line.rstrip("\n\r")
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
        if not payloads:
            logger.error(f"[!] Payload file '{path}' is empty.")
            sys.exit(1)
        return payloads
    return [path]


def load_targets(args: argparse.Namespace, logger: logging.Logger) -> list[str]:
    targets: list[str] = []
    if args.url:
        targets.append(args.url.strip())
    if args.file:
        if not os.path.isfile(args.file):
            logger.error(f"[!] URL file not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
            targets.extend(line.strip() for line in fh if line.strip())
    seen, deduped = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    if not deduped:
        logger.error("[!] No targets provided. Use --url or --file.")
        sys.exit(1)
    return deduped


def parse_cookie_string(cookie_str: str) -> dict:
    cookies = {}
    for pair in (cookie_str or "").split(";"):
        pair = pair.strip()
        if pair and "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def mask_secret(value: str) -> str:
    """Never print cookie/header values, even in verbose mode -- only
    that something was set and how many characters it was."""
    if not value:
        return "(none)"
    return f"<set, {len(value)} chars>"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reflectra.py",
        description="Reflectra - context-aware XSS scanner with browser confirmation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    tgt = p.add_argument_group("target selection")
    tgt.add_argument("-u", "--url", help="Single target URL to scan")
    tgt.add_argument("-f", "--file", help="File containing one target URL per line")

    scan = p.add_argument_group("scan options")
    scan.add_argument("-p", "--payload", default=DEFAULT_PAYLOAD_FILE,
                       help="Payload file path, or a single literal payload string")
    scan.add_argument("-t", "--threads", type=int, default=5, help="Concurrent browser worker threads")
    scan.add_argument("--timeout", type=float, default=2.0, help="Seconds to wait for a JS dialog")
    scan.add_argument("--max-payloads-per-point", type=int, default=0,
                       help="Cap payloads tried per injection point (0 = no cap, i.e. FULL original coverage, "
                            "context-matched payloads just run first)")
    scan.add_argument("--no-context-filter", action="store_true",
                       help="Skip phase-1 reflection probing entirely; run the full original payload list "
                            "against every point exactly like v1 did")
    scan.add_argument("--no-sink-probe", action="store_true", help="Disable DOM-sink static analysis on non-firing payloads")
    scan.add_argument("--skip-unreflected", action="store_true",
                       help="Don't sample unreflected params at all (faster, may miss pure client-side DOM XSS)")
    scan.add_argument("--max-confirmed", type=int, default=None,
                       help="Stop scanning after this many CONFIRMED XSS findings (cancels remaining queued tasks). "
                            "Default: unbounded (scan runs to completion)")
    scan.add_argument("--stop-on-first-confirmed", action="store_true",
                       help="Shorthand for --max-confirmed 1")

    auth = p.add_argument_group("authentication")
    auth.add_argument("--cookie", help="Cookie header string, e.g. \"session=abc; role=user\"")
    auth.add_argument("--header", action="append", default=[], help="Extra header 'Name: value', repeatable")
    auth.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")

    blind = p.add_argument_group("blind / stored XSS")
    blind.add_argument("--blind-url", help="External out-of-band collector URL (Burp Collaborator, Interactsh, "
                                            "xss.report, self-hosted XSS Hunter Express). Reflectra injects payloads "
                                            "pointing at this URL; confirmation happens on YOUR collector, not here.")
    blind.add_argument("--blind-only", action="store_true", help="Only run blind injection, skip live browser confirmation")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output",
                      help="Report file path (.json, .html, or .txt). If omitted, Reflectra auto-saves an HTML "
                           "report into ./reports/, named after the target and timestamp")
    out.add_argument("--report-style", choices=["default", "hacker"], default="hacker",
                      help="HTML report visual style. 'hacker' = dark terminal/CRT theme grouped by bug class "
                           "(only applies when --output ends in .html)")
    out.add_argument("--plain", action="store_true", help="Disable ANSI colors / ASCII banner in terminal output")
    out.add_argument("-v", "--verbose", action="store_true")
    out.add_argument("--no-banner", action="store_true")
    out.add_argument("--version", action="version", version=f"Reflectra {VERSION}")

    tg = p.add_argument_group("telegram delivery")
    tg.add_argument("--telegram-token", help="Telegram bot token (from @BotFather). Saved locally after first use "
                                              "so you're never asked twice -- see ~/.reflectra/config.json")
    tg.add_argument("--telegram-chat-id", help="Telegram chat/channel ID to deliver the final report to")
    tg.add_argument("--forget-telegram", action="store_true", help="Delete saved Telegram credentials and exit")

    wiz = p.add_argument_group("interactive mode")
    wiz.add_argument("--wizard", action="store_true",
                      help="Force the interactive one-click wizard even if other flags are also given")
    return p


def deliver_results(engine, plan_stats, args, logger, target_label: str) -> None:
    """Terminal results table + summary + report file (default or hacker-
    themed) + optional Telegram delivery. Additive presentation/delivery
    layer only -- does not touch engine.findings or plan_stats, just reads
    and forwards them.

    If no output path was given, a report is ALWAYS auto-saved as HTML into
    ./reports/, named after the target -- there is no "no report" case."""
    print_results_table(engine)
    print_summary_block(engine, plan_stats)

    report_path = args.output
    auto_named = False
    if not report_path:
        report_path = naming.auto_report_path(target_label, ext=".html")
        auto_named = True

    ext = os.path.splitext(report_path)[1].lower()
    if ext in (".html", ".htm") and args.report_style == "hacker":
        write_hacker_report(engine, plan_stats, report_path, target_label)
    else:
        write_report(engine, report_path, logger, plan_stats)
    logger.info(f"[i] Report saved to {report_path}" + (" (auto-named)" if auto_named else ""))

    telegram_token = args.telegram_token
    telegram_chat = args.telegram_chat_id
    if not (telegram_token and telegram_chat):
        # Fall back to saved credentials so the user is never asked twice.
        saved_token, saved_chat = cfgmod.get_telegram_creds()
        if saved_token and saved_chat:
            telegram_token, telegram_chat = saved_token, saved_chat

    if telegram_token and telegram_chat:
        logger.info(f"[i] Telegram delivery: token={mask_secret(telegram_token)} "
                     f"chat_id={mask_secret(telegram_chat)}")
        ok = telegram_notify.notify(
            telegram_token, telegram_chat, engine, plan_stats, logger,
            report_path=report_path, target_label=target_label,
        )
        if ok:
            logger.info("[i] Telegram: summary delivered.")
            # Persist credentials only after a real successful send, and only
            # if they came from --telegram-token/--telegram-chat-id this run
            # (i.e. weren't already the saved ones) so we save silently once.
            if args.telegram_token and args.telegram_chat_id:
                cfgmod.save_telegram_creds(args.telegram_token, args.telegram_chat_id)
        else:
            logger.warning("[!] Telegram: delivery failed -- check token/chat_id and network access.")


def main() -> int:
    raw_args = sys.argv[1:]

    if "--forget-telegram" in raw_args:
        cfgmod.clear_telegram_creds()
        print(f"Saved Telegram credentials removed from {cfgmod.config_path_display()}.")
        return 0

    # No arguments at all, or explicit --wizard -> interactive one-click mode.
    if not raw_args or "--wizard" in raw_args:
        print_banner(VERSION)
        args = run_wizard(DEFAULT_PAYLOAD_FILE)
    else:
        args = build_arg_parser().parse_args()
        if not args.url and not args.file:
            build_arg_parser().error("You must specify a target with --url or --file (or run with no arguments "
                                       "for the interactive wizard).")

    logger = setup_logging(args.verbose)
    if args.plain:
        os.environ["NO_COLOR"] = "1"
    if not args.no_banner and raw_args:  # wizard already printed its own banner
        print_banner(VERSION)

    targets = load_targets(args, logger)
    payloads = load_payloads(args.payload, logger)
    logger.info(f"[i] Loaded {len(targets)} target(s), {len(payloads)} payload(s)")

    cookies = parse_cookie_string(args.cookie) if args.cookie else {}
    if args.verbose and args.cookie:
        logger.debug(f"[i] Cookie auth: {mask_secret(args.cookie)}")

    # --- Blind XSS mode --------------------------------------------------
    if args.blind_url:
        all_points = [pt for url in targets for pt in injection_points(url)]
        blind_payloads = build_blind_payloads(args.blind_url)
        blind_engine = BrowserConfirmationEngine(args.threads, args.timeout, logger, cookies=cookies, insecure=args.insecure)
        blind_engine.run_blind_injection(all_points, blind_payloads, logger)
        if args.blind_only:
            return 0

    # --- Phase 1: reflection probing (Target Manager + Injection Discovery
    #     + Reflection Probe stages) --------------------------------------
    if args.no_context_filter:
        logger.info("[i] --no-context-filter set: skipping probe, using full original payload coverage")
        probe_results = brute_force_probe_results(targets)
    else:
        session = build_session(args.cookie, args.header, args.insecure)
        probe_results = {}
        for url in targets:
            logger.info(f"[i] Probing {url}")
            probe_results[url] = probe_target(url, session, logger)

    # --- Payload Planner ---------------------------------------------------
    max_pp = args.max_payloads_per_point or None
    tasks, plan_stats = plan_tasks(probe_results, payloads, max_pp, args.skip_unreflected, logger)

    if not tasks:
        logger.info("[i] No candidate injection points found. Nothing to confirm in-browser.")
        return 0

    # --- Original Browser Confirmation Engine ------------------------------
    max_confirmed = getattr(args, "max_confirmed", None)
    stop_first = getattr(args, "stop_on_first_confirmed", False)
    if max_confirmed is None and stop_first:
        max_confirmed = 1
    engine = BrowserConfirmationEngine(
        args.threads, args.timeout, logger,
        cookies=cookies, insecure=args.insecure,
        probe_sinks=not args.no_sink_probe, verbose=args.verbose,
        max_confirmed=max_confirmed,
        on_finding=lambda f: print_finding_live(f.kind, f.context, f.injected_url),
    )
    try:
        engine.run(tasks)
    except KeyboardInterrupt:
        logger.info("\n[i] Interrupted -- delivering results gathered so far.")
        deliver_results(engine, plan_stats, args, logger, target_label=", ".join(targets))
        return 130
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[!] Fatal error during scan: {exc}")
        return 1

    deliver_results(engine, plan_stats, args, logger, target_label=", ".join(targets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
