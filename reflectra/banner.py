"""
reflectra.banner
-------------------
Terminal presentation only -- ASCII banner + colorized summary block. Purely
cosmetic and additive: does not touch probing/planning/detection logic, only
formats what engine/plan_stats already produced.

Falls back to plain (no ANSI) output automatically if the terminal doesn't
support color (e.g. piped to a file, Windows cmd without ANSI, NO_COLOR set),
so CI logs and redirected output stay clean.
"""

from __future__ import annotations

import os
import sys

from .models import FindingKind


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("REFLECTRA_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


class C:
    def __init__(self, enabled: bool):
        self.e = enabled

    def __call__(self, code: str, text: str) -> str:
        if not self.e:
            return text
        return f"\033[{code}m{text}\033[0m"

    def green(self, t): return self("1;32", t)
    def dim_green(self, t): return self("2;32", t)
    def amber(self, t): return self("1;33", t)
    def cyan(self, t): return self("1;36", t)
    def red(self, t): return self("1;31", t)
    def bold(self, t): return self("1", t)
    def dim(self, t): return self("2", t)


ASCII_BANNER = r"""
██████╗ ███████╗███████╗██╗     ███████╗ ██████╗████████╗██████╗  █████╗
██╔══██╗██╔════╝██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
██████╔╝█████╗  █████╗  ██║     █████╗  ██║        ██║   ██████╔╝███████║
██╔══██╗██╔══╝  ██╔══╝  ██║     ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║
██║  ██║███████╗██║     ███████╗███████╗╚██████╗   ██║   ██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
"""


def print_banner(version: str) -> None:
    c = C(_color_enabled())
    print(c.green(ASCII_BANNER))
    print(c.dim(f"        Context-Aware XSS Scanner  |  v{version}  |  by Pratik Khairnar"))
    print(c.dim("        github.com/pratik-khairnar-sec"))
    print(c.dim_green("        " + "-" * 60))


def print_phase(label: str) -> None:
    c = C(_color_enabled())
    print(c.cyan(f"\n[>] {label}"))


def print_finding_live(kind: FindingKind, context: str, url: str) -> None:
    """Live-feed line for a single finding, hacker-terminal style. Wired
    into the CLI via BrowserConfirmationEngine's on_finding callback."""
    c = C(_color_enabled())
    tag = {
        FindingKind.CONFIRMED_XSS: c.green("[CONFIRMED]"),
        FindingKind.SINK_REACHABLE_LEAD: c.amber("[SINK-LEAD]"),
        FindingKind.BLIND_INJECTION: c.cyan("[BLIND-SENT]"),
        FindingKind.ERROR: c("2;31", "[ERROR]"),
    }.get(kind, "[?]")
    short = url if len(url) < 110 else url[:107] + "..."
    print(f"    {tag} {c.dim('[' + context + ']')} {short}")


def print_results_table(engine) -> None:
    """Final colorized results table -- one row per finding, distinct color
    per kind, run right before the summary block."""
    c = C(_color_enabled())
    if not engine.findings:
        print(c.dim("  (no findings to display)"))
        return

    color_for = {
        FindingKind.CONFIRMED_XSS: c.green,
        FindingKind.SINK_REACHABLE_LEAD: c.amber,
        FindingKind.BLIND_INJECTION: c.cyan,
        FindingKind.ERROR: c.red,
    }

    col_kind, col_ctx, col_url = 21, 14, 70
    header = f"  {'KIND':<{col_kind}} {'CONTEXT':<{col_ctx}} {'URL'}"
    print(c.bold(header))
    print(c.dim_green("  " + "-" * (col_kind + col_ctx + col_url + 2)))
    for f in engine.findings:
        paint = color_for.get(f.kind, c.dim)
        kind_s = f.kind.value[:col_kind]
        ctx_s = (f.context or "")[:col_ctx]
        url_s = f.injected_url if len(f.injected_url) <= col_url else f.injected_url[: col_url - 3] + "..."
        print(f"  {paint(f'{kind_s:<{col_kind}}')} {ctx_s:<{col_ctx}} {url_s}")


def print_summary_block(engine, plan_stats) -> None:
    c = C(_color_enabled())
    confirmed = sum(1 for f in engine.findings if f.kind == FindingKind.CONFIRMED_XSS)
    leads = sum(1 for f in engine.findings if f.kind == FindingKind.SINK_REACHABLE_LEAD)
    blind = sum(1 for f in engine.findings if f.kind == FindingKind.BLIND_INJECTION)
    errors = max(
        sum(1 for f in engine.findings if f.kind == FindingKind.ERROR),
        engine.stats.total_errors,
    )

    print(c.dim_green("\n" + "=" * 64))
    print(c.bold("  SCAN COMPLETE"))
    print(c.dim_green("=" * 64))
    if plan_stats is not None:
        print(c.dim(f"  points probed          : {plan_stats.total_points}"))
        print(c.dim(f"    reflected (ctx ok)     : {plan_stats.reflected_points}"))
        print(c.dim(f"    ambiguous              : {plan_stats.ambiguous_points}"))
        print(c.dim(f"    not reflected          : {plan_stats.not_reflected_points}"))
        print(c.dim(f"    probe failed(fallback) : {plan_stats.fallback_points}"))
        print(c.dim(f"  browser tasks planned  : {plan_stats.total_tasks}"))
    print(f"  {c.bold('CONFIRMED XSS')}          : {c.green(str(confirmed))}")
    print(f"  {c.bold('SINK-REACHABLE LEADS')} : {c.amber(str(leads))}  (unconfirmed)")
    print(f"  {c.bold('BLIND INJECTIONS')}     : {c.cyan(str(blind))}  (unconfirmed)")
    print(f"  {c.bold('ERRORS')}               : {c.red(str(errors))}  (not 'not vulnerable')")
    print(c.dim(f"  browser requests sent  : {engine.stats.total_requests}"))
    print(c.dim(f"  time taken             : {engine.stats.elapsed}s"))
    print(c.dim_green("=" * 64))
