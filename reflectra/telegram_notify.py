"""
reflectra.telegram_notify
----------------------------
Optional delivery of the final scan report/summary to Telegram via the
standard Bot API. Additive and opt-in only (--telegram-token / --telegram-chat-id) --
does nothing unless both are supplied. No detection/probing/planning code
depends on this module or is aware of it.

Setup (one-time, on the user's side):
  1. Message @BotFather on Telegram, /newbot, get a bot token.
  2. Message your new bot once (or add it to a group), then GET
     https://api.telegram.org/bot<token>/getUpdates to find your chat_id.
  3. Pass --telegram-token <token> --telegram-chat-id <id> to reflectra.py.

Token/chat-id are never logged in full -- only masked, same convention as
--cookie/--header in probe.py/reflectra.py.
"""

from __future__ import annotations

import logging
import os

import requests

API_BASE = "https://api.telegram.org"


def mask(value: str) -> str:
    if not value:
        return "(none)"
    return f"<set, {len(value)} chars>"


def send_message(token: str, chat_id: str, text: str, logger: logging.Logger, parse_mode: str = "HTML") -> bool:
    """Send a text message (Telegram caps ~4096 chars; caller should keep
    summaries short and attach the full report as a document instead)."""
    if not token or not chat_id:
        return False
    url = f"{API_BASE}/bot{token}/sendMessage"
    try:
        resp = requests.post(
            url,
            data={"chat_id": chat_id, "text": text[:4000], "parse_mode": parse_mode, "disable_web_page_preview": True},
            timeout=15,
        )
        if resp.status_code != 200:
            logger.warning(f"[telegram] sendMessage failed: HTTP {resp.status_code} :: {resp.text[:200]}")
            return False
        return True
    except requests.RequestException as exc:
        logger.warning(f"[telegram] sendMessage error: {exc}")
        return False


def send_document(token: str, chat_id: str, file_path: str, caption: str, logger: logging.Logger) -> bool:
    """Send a file (e.g. the HTML/JSON report) as a document attachment."""
    if not token or not chat_id:
        return False
    if not os.path.isfile(file_path):
        logger.warning(f"[telegram] report file not found: {file_path}")
        return False
    url = f"{API_BASE}/bot{token}/sendDocument"
    try:
        with open(file_path, "rb") as fh:
            resp = requests.post(
                url,
                data={"chat_id": chat_id, "caption": caption[:1000]},
                files={"document": (os.path.basename(file_path), fh)},
                timeout=60,
            )
        if resp.status_code != 200:
            logger.warning(f"[telegram] sendDocument failed: HTTP {resp.status_code} :: {resp.text[:200]}")
            return False
        return True
    except requests.RequestException as exc:
        logger.warning(f"[telegram] sendDocument error: {exc}")
        return False


def build_summary_text(engine, plan_stats, target_label: str = "") -> str:
    """Short HTML-formatted summary for a Telegram chat message (kept well
    under the 4096-char limit; the full report goes as an attached document)."""
    from .models import FindingKind

    confirmed = sum(1 for f in engine.findings if f.kind == FindingKind.CONFIRMED_XSS)
    leads = sum(1 for f in engine.findings if f.kind == FindingKind.SINK_REACHABLE_LEAD)
    blind = sum(1 for f in engine.findings if f.kind == FindingKind.BLIND_INJECTION)
    errors = max(sum(1 for f in engine.findings if f.kind == FindingKind.ERROR), engine.stats.total_errors)

    lines = [
        "<b>Reflectra scan complete</b>",
        f"Target: <code>{target_label or 'as configured'}</code>",
        "",
        f"CONFIRMED XSS: <b>{confirmed}</b>",
        f"Sink-reachable leads: {leads} (unconfirmed)",
        f"Blind injections sent: {blind} (unconfirmed)",
        f"Errors: {errors}",
        f"Requests sent: {engine.stats.total_requests}",
        f"Time: {engine.stats.elapsed}s",
    ]
    if confirmed:
        lines.append("")
        lines.append("Top confirmed URL(s):")
        for f in [x for x in engine.findings if x.kind == FindingKind.CONFIRMED_XSS][:5]:
            lines.append(f"- <code>{f.injected_url[:150]}</code>")
    return "\n".join(lines)


def notify(token: str, chat_id: str, engine, plan_stats, logger: logging.Logger,
           report_path: str | None = None, target_label: str = "") -> bool:
    """High-level entry point used by the CLI: send a summary message, and
    if a report file was written, attach it as a document too. Returns True
    only if the summary message was delivered successfully."""
    summary = build_summary_text(engine, plan_stats, target_label)
    ok = send_message(token, chat_id, summary, logger)
    if ok and report_path:
        send_document(token, chat_id, report_path, caption="Reflectra full report", logger=logger)
    return ok
