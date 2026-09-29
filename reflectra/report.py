from __future__ import annotations

import json
import os
from datetime import datetime

from .browser import BrowserConfirmationEngine, VERSION
from .models import FindingKind


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _counts(engine: BrowserConfirmationEngine) -> dict:
    c = {k: 0 for k in FindingKind}
    for f in engine.findings:
        c[f.kind] += 1
    return c


def print_summary(engine: BrowserConfirmationEngine, plan_stats, logger) -> None:
    c = _counts(engine)
    print()
    print("-" * 60)
    print("Scan finished.")
    if plan_stats is not None:
        print(f"  Injection points probed : {plan_stats.total_points}")
        print(f"    reflected (context OK) : {plan_stats.reflected_points}")
        print(f"    ambiguous               : {plan_stats.ambiguous_points}")
        print(f"    not reflected           : {plan_stats.not_reflected_points}")
        print(f"    probe failed (fallback) : {plan_stats.fallback_points}")
        print(f"  Browser tasks planned    : {plan_stats.total_tasks}")
    print(f"  Confirmed XSS            : {c[FindingKind.CONFIRMED_XSS]}")
    print(f"  Sink-reachable leads     : {c[FindingKind.SINK_REACHABLE_LEAD]}  (unconfirmed -- manual review)")
    print(f"  Blind injections sent    : {c[FindingKind.BLIND_INJECTION]}  (unconfirmed -- check external collector)")
    print(f"  Errors                   : {max(c[FindingKind.ERROR], engine.stats.total_errors)}  (NOT the same as 'not vulnerable')")
    print(f"  Browser requests sent    : {engine.stats.total_requests}")
    print(f"  Time taken               : {engine.stats.elapsed}s")
    print("-" * 60)


def write_report(engine: BrowserConfirmationEngine, output_path: str, logger, plan_stats=None) -> None:
    ext = os.path.splitext(output_path)[1].lower()
    try:
        if ext == ".json":
            _write_json(engine, output_path, plan_stats)
        elif ext in (".html", ".htm"):
            _write_html(engine, output_path, plan_stats)
        else:
            _write_text(engine, output_path, plan_stats)
    except OSError as exc:
        logger.error(f"[!] Failed to write report: {exc}")
        return
    logger.info(f"[i] Report saved to {output_path}")


def _write_json(engine: BrowserConfirmationEngine, path: str, plan_stats) -> None:
    c = _counts(engine)
    data = {
        "tool": "Reflectra",
        "version": VERSION,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "plan_stats": plan_stats.__dict__ if plan_stats else None,
        "summary": {
            "confirmed_xss": c[FindingKind.CONFIRMED_XSS],
            "sink_reachable_leads": c[FindingKind.SINK_REACHABLE_LEAD],
            "blind_injections": c[FindingKind.BLIND_INJECTION],
            "errors": max(c[FindingKind.ERROR], engine.stats.total_errors),
            "requests_sent": engine.stats.total_requests,
            "time_taken_seconds": engine.stats.elapsed,
        },
        "findings": [
            {
                "kind": f.kind.value,
                "target_url": f.target_url,
                "payload": f.payload,
                "injected_url": f.injected_url,
                "context": f.context,
                "dialog_text": f.dialog_text,
                "detail": f.detail,
                "timestamp": f.timestamp,
            }
            for f in engine.findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _write_text(engine: BrowserConfirmationEngine, path: str, plan_stats) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("Reflectra Scan Report\n")
        fh.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n\n")
        for f in engine.findings:
            fh.write(f"[{f.kind.value}] {f.injected_url}\n")
            fh.write(f"  Target   : {f.target_url}\n")
            fh.write(f"  Context  : {f.context}\n")
            fh.write(f"  Payload  : {f.payload}\n")
            if f.dialog_text:
                fh.write(f"  Dialog   : {f.dialog_text}\n")
            if f.detail:
                fh.write(f"  Detail   : {f.detail}\n")
            fh.write(f"  Time     : {f.timestamp}\n\n")


def _write_html(engine: BrowserConfirmationEngine, path: str, plan_stats) -> None:
    rows = "\n".join(
        f"""<tr class="{f.kind.value}">
            <td>{i + 1}</td>
            <td>{f.kind.value}</td>
            <td class="mono">{_escape(f.target_url)}</td>
            <td class="mono">{_escape(f.injected_url)}</td>
            <td>{_escape(f.context)}</td>
            <td class="mono">{_escape(f.payload)}</td>
            <td>{_escape(f.dialog_text or f.detail)}</td>
        </tr>"""
        for i, f in enumerate(engine.findings)
    )
    c = _counts(engine)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Reflectra Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0d1117; color:#c9d1d9; margin:2rem; }}
  h1 {{ color:#58a6ff; }}
  .summary {{ background:#161b22; padding:1rem 1.5rem; border-radius:8px; margin-bottom:1.5rem; }}
  table {{ width:100%; border-collapse:collapse; background:#161b22; }}
  th, td {{ padding:0.5rem 0.7rem; border-bottom:1px solid #30363d; text-align:left; font-size:0.82rem; }}
  th {{ background:#21262d; color:#58a6ff; }}
  tr.CONFIRMED_XSS td:nth-child(2) {{ color:#3fb950; font-weight:600; }}
  tr.SINK_REACHABLE_LEAD td:nth-child(2) {{ color:#d29922; font-weight:600; }}
  tr.ERROR td:nth-child(2) {{ color:#f85149; font-weight:600; }}
  tr.BLIND_INJECTION td:nth-child(2) {{ color:#79c0ff; font-weight:600; }}
  .mono {{ font-family: Consolas, monospace; word-break:break-all; }}
  footer {{ margin-top:2rem; color:#6e7681; font-size:0.8rem; }}
</style></head>
<body>
  <h1>Reflectra &mdash; Scan Report</h1>
  <div class="summary">
    <div>Generated: {datetime.now().isoformat(timespec='seconds')}</div>
    <div>Confirmed XSS: <b>{c[FindingKind.CONFIRMED_XSS]}</b> &nbsp;|&nbsp;
         Sink-reachable leads: <b>{c[FindingKind.SINK_REACHABLE_LEAD]}</b> &nbsp;|&nbsp;
         Blind injections: <b>{c[FindingKind.BLIND_INJECTION]}</b> &nbsp;|&nbsp;
         Errors: <b>{c[FindingKind.ERROR]}</b></div>
    <div>Requests sent: {engine.stats.total_requests} | Time: {engine.stats.elapsed}s</div>
    <div style="color:#8b949e;font-size:0.78rem;margin-top:0.5rem;">
      Sink-reachable and blind-injection rows are UNCONFIRMED leads, not proven vulnerabilities.
      Error rows mean a payload could not be tested -- they are not "not vulnerable".</div>
  </div>
  <table>
    <thead><tr><th>#</th><th>Kind</th><th>Target</th><th>Injected URL</th><th>Context</th><th>Payload</th><th>Dialog / Detail</th></tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="7">No findings.</td></tr>'}</tbody>
  </table>
  <footer>Generated by Reflectra v{VERSION}</footer>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
