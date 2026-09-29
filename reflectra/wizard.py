"""
reflectra.wizard
-------------------
Interactive "one-click" mode: run `python3 reflectra.py` with no arguments
and it asks a short series of y/n and fill-in questions instead of
requiring the user to remember CLI flags. Every question has a sensible
default (just press Enter). Telegram is asked only once ever -- if
credentials are already saved (reflectra.config), it just confirms
whether to use them for this run.

This is the primary, intended way to run Reflectra day-to-day -- the full
flag reference in reflectra.py exists for scripting/CI, not as the normal
front door. This module only builds an argparse.Namespace equivalent to
what the CLI flags would have produced -- it does not contain any
detection/probing logic itself.
"""

from __future__ import annotations

import argparse

from . import config as cfgmod
from .banner import C, _color_enabled


def _c() -> C:
    return C(_color_enabled())


def _step(n: int, total: int, label: str) -> None:
    c = _c()
    print(c.dim(f"\n  [{n}/{total}]") + " " + c.bold(label))


def _ask(prompt: str, default: str = "") -> str:
    c = _c()
    suffix = c.dim(f" [{default}]") if default else ""
    val = input(f"  {c.green('>')} {prompt}{suffix}: ").strip()
    return val if val else default


def _ask_yn(prompt: str, default_yes: bool = True) -> bool:
    c = _c()
    hint = c.green("Y") + "/n" if default_yes else "y/" + c.red("N")
    val = input(f"  {c.green('>')} {prompt} ({hint}): ").strip().lower()
    if not val:
        return default_yes
    return val.startswith("y")


def run_wizard(default_payload_file: str) -> argparse.Namespace:
    c = _c()
    print()
    print(c.dim_green("  " + "=" * 62))
    print("  " + c.bold("ONE-CLICK SETUP") + c.dim("  --  press Enter to accept the [default]"))
    print(c.dim_green("  " + "=" * 62))

    total = 6

    _step(1, total, "Target")
    url = _ask("Target URL (e.g. https://target.tld/search?q=1)")
    while not url:
        print(c.red("    A target URL is required."))
        url = _ask("Target URL")

    _step(2, total, "Scan speed")
    threads = _ask("Threads (concurrent browser workers)", "5")
    timeout = _ask("Dialog wait timeout in seconds", "2.0")
    full_coverage = _ask_yn("Use full original payload coverage (slower, most thorough)?", default_yes=False)

    _step(3, total, "Authentication")
    auth = _ask_yn("Does this target need authentication (cookie/header)?", default_yes=False)
    cookie = None
    if auth:
        cookie = _ask("Cookie string (e.g. session=abc; role=user)")

    _step(4, total, "Stop condition")
    max_confirmed_raw = _ask("Stop after this many confirmed XSS findings (0 = don't stop, run to completion)", "5")
    try:
        max_confirmed = int(max_confirmed_raw)
        if max_confirmed <= 0:
            max_confirmed = None
    except ValueError:
        max_confirmed = 5

    _step(5, total, "Blind / stored XSS")
    blind = _ask_yn("Also send blind/stored XSS payloads to an external collector?", default_yes=False)
    blind_url = None
    if blind:
        blind_url = _ask("Collector URL (Burp Collaborator / Interactsh / xss.report / etc.)")

    _step(6, total, "Telegram delivery")
    saved_token, saved_chat = cfgmod.get_telegram_creds()
    telegram_token, telegram_chat = None, None
    if saved_token and saved_chat:
        masked_chat = saved_chat[:3] + "***" if len(saved_chat) > 3 else "***"
        use_saved = _ask_yn(f"Send the final report to your saved Telegram chat ({masked_chat})?", default_yes=True)
        if use_saved:
            telegram_token, telegram_chat = saved_token, saved_chat
    else:
        want_tg = _ask_yn("Send the final report to Telegram? (asked once, saved for next time)", default_yes=False)
        if want_tg:
            telegram_token = _ask("Telegram bot token (from @BotFather)")
            telegram_chat = _ask("Telegram chat ID")
            if telegram_token and telegram_chat:
                cfgmod.save_telegram_creds(telegram_token, telegram_chat)
                print(c.dim(f"    Saved to {cfgmod.config_path_display()} -- you won't be asked again."))

    print(c.dim("\n  A hacker-themed HTML report will be auto-saved into ./reports/ when the scan finishes."))
    print(c.green("  Starting scan...\n"))
    print(c.dim_green("  " + "=" * 62))

    ns = argparse.Namespace(
        url=url,
        file=None,
        payload=default_payload_file,
        threads=int(threads) if threads.isdigit() else 5,
        timeout=float(timeout) if _is_float(timeout) else 2.0,
        max_payloads_per_point=0,
        no_context_filter=full_coverage,
        no_sink_probe=False,
        skip_unreflected=False,
        cookie=cookie,
        header=[],
        insecure=False,
        blind_url=blind_url,
        blind_only=False,
        output=None,  # always auto-named into ./reports/
        report_style="hacker",
        plain=False,
        verbose=False,
        no_banner=False,
        telegram_token=telegram_token,
        telegram_chat_id=telegram_chat,
        max_confirmed=max_confirmed,
        stop_on_first_confirmed=False,
        forget_telegram=False,
        wizard=False,
    )
    return ns


def _is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False
