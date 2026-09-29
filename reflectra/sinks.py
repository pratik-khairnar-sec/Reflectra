"""
reflectra.sinks
----------------
Lightweight DOM-sink static analysis.

This is NOT taint analysis and does not execute or trace data flow through
JavaScript. It answers a narrower, cheaper question: "did our marker end up
inside source text that is passed to a known-dangerous DOM sink?" That is
enough to flag likely DOM XSS that a CSP or missing-user-interaction
condition suppressed from firing as a live alert() dialog -- cases the
original alert-only detector silently reported as "not vulnerable".

Findings from this module are always reported as MEDIUM/INFO confidence
("sink-reachable") rather than CONFIRMED, because we have not proven
attacker control of the value reaching the sink beyond marker placement --
only that the marker's bytes appear inside a call to a dangerous sink.
Treat these as manual-review leads, not confirmed vulnerabilities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DANGEROUS_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval",
    "setTimeout",
    "setInterval",
    "Function(",
    "insertAdjacentHTML",
    "location.href",
    "location.assign",
    "location.replace",
    "$(",  # jQuery selector/HTML sink -- broad, kept low-confidence
    ".html(",
]

_SINK_CALL_RE = {
    sink: re.compile(re.escape(sink) + r"\s*\(?[^;]{0,200}", re.IGNORECASE)
    for sink in DANGEROUS_SINKS
}


@dataclass
class SinkFinding:
    sink: str
    snippet: str


def find_reachable_sinks(page_source: str, marker: str) -> list[SinkFinding]:
    """Scan raw page source (post-render DOM serialization, ideally) for
    dangerous sink calls whose nearby argument text contains the marker."""
    findings: list[SinkFinding] = []
    if marker not in page_source:
        return findings

    for sink, pattern in _SINK_CALL_RE.items():
        for m in pattern.finditer(page_source):
            window = page_source[m.start(): m.start() + 400]
            if marker in window:
                snippet = window.strip().replace("\n", " ")
                findings.append(SinkFinding(sink=sink, snippet=snippet[:200]))

    return findings


JS_SINK_PROBE = r"""
try {
    const marker = arguments[0];
    const hits = [];
    const html = document.documentElement.outerHTML;
    if (html.includes(marker)) {
        hits.push({sink: 'DOM outerHTML', snippet: html.substring(
            Math.max(0, html.indexOf(marker) - 60), html.indexOf(marker) + 60)});
    }
    return hits;
} catch (e) {
    return [];
}
"""
