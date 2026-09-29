"""
reflectra.context
------------------
Reflection-context detection and context-aware payload classification.

Instead of firing every payload at every parameter (O(targets x payloads)),
Reflectra first sends a unique, harmless marker into each parameter over
plain HTTP, then inspects *where and how* that marker landed in the
response.

IMPORTANT: classify_reflection() only ever runs on a body that was
successfully fetched -- it has no concept of network failure. Whether a
probe request succeeded, timed out, or errored is decided in probe.py and
represented as a models.ProbeState. This module answers a narrower
question: given a response body we DID get, where does the marker sit in
it. It never returns "not reflected" for a request that never completed.

This is a heuristic classifier, not a full HTML/JS parser. It is
deliberately conservative: when context is ambiguous it falls back to
"unknown", and reflectra.planner treats "unknown" as "run broad coverage",
never as "skip this payload".
"""

from __future__ import annotations

import re
from typing import Optional

from .models import ProbeState, ReflectionResult

MARKER_PREFIX = "rfx"


def make_marker() -> str:
    import uuid
    return f"{MARKER_PREFIX}{uuid.uuid4().hex[:10]}"



_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]*>")


def _find_all_positions(haystack: str, needle: str) -> list[int]:
    positions = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + len(needle)
    return positions


def classify_reflection(body: str, marker: str) -> ReflectionResult:
    """Determine every context in which `marker` was reflected in `body`.
    Only call this with a body that was actually fetched successfully --
    network-level outcomes are handled by the caller (probe.py) as separate
    ProbeStates, never funneled through this function."""
    if marker not in body and marker.replace("&", "&amp;") not in body:
        return ReflectionResult(marker, ProbeState.NOT_REFLECTED, set(), 0, False, False)

    contexts: set[str] = set()
    occurrences = 0
    html_encoded = "&lt;" in body and marker in body  # crude signal only
    js_string_escaped = False

    # Script-block reflections (checked first: most impactful).
    for m in _SCRIPT_BLOCK_RE.finditer(body):
        script_src = m.group(1)
        if marker in script_src:
            contexts.add("script")
            occurrences += script_src.count(marker)
            # crude check: is it sitting inside a quoted JS string literal?
            for q in ('"', "'", "`"):
                pattern = re.escape(q) + r"[^" + re.escape(q) + r"]*" + re.escape(marker)
                if re.search(pattern, script_src):
                    js_string_escaped = True

    # Comment reflections (low value, still worth flagging for context leaks).
    for m in _COMMENT_RE.finditer(body):
        if marker in m.group(1):
            contexts.add("comment")
            occurrences += m.group(1).count(marker)

    # Attribute-context reflections: look inside tag definitions.
    for m in _TAG_RE.finditer(body):
        tag = m.group(0)
        if marker not in tag:
            continue
        occurrences += tag.count(marker)
        if re.search(r'="[^"]*' + re.escape(marker), tag):
            contexts.add("attr-dq")
        if re.search(r"='[^']*" + re.escape(marker), tag):
            contexts.add("attr-sq")
        if re.search(r"=[^'\"\s>]*" + re.escape(marker), tag):
            contexts.add("attr-uq")
        if re.search(r'(?:href|src|action|formaction)\s*=\s*["\']?[^"\'>]*' + re.escape(marker), tag, re.IGNORECASE):
            contexts.add("uri")

    # Plain HTML text-node reflection (outside any tag/script/comment already counted).
    stripped = _TAG_RE.sub(" ", _SCRIPT_BLOCK_RE.sub(" ", _COMMENT_RE.sub(" ", body)))
    if marker in stripped:
        contexts.add("html")
        occurrences += stripped.count(marker)

    if not contexts:
        # Reflected somewhere we couldn't classify confidently -- don't drop it,
        # mark AMBIGUOUS so the planner runs broad coverage for this point.
        contexts.add("unknown")
        occurrences = max(occurrences, len(_find_all_positions(body, marker)))
        return ReflectionResult(marker, ProbeState.AMBIGUOUS, contexts, occurrences, html_encoded, js_string_escaped)

    return ReflectionResult(marker, ProbeState.REFLECTED, contexts, occurrences, html_encoded, js_string_escaped)


# --------------------------------------------------------------------------- #
# Payload context tagging
# --------------------------------------------------------------------------- #

# Cheap heuristics to bucket an arbitrary payload string into the contexts
# it is designed to break out of. A payload can match more than one bucket.
_TAG_BREAK_RE = re.compile(r"<\s*/?\s*[a-zA-Z]")
_DQ_BREAK_RE = re.compile(r'"\s*[>\s]|"\s*[a-zA-Z-]+\s*=')
_SQ_BREAK_RE = re.compile(r"'\s*[>\s]|'\s*[a-zA-Z-]+\s*=")
_UQ_BREAK_RE = re.compile(r"^[^\"'<>\s]+(\s+on\w+=|\s*/?>)")
_URI_RE = re.compile(r"^\s*javascript:", re.IGNORECASE)
_JS_BREAK_RE = re.compile(r"^\s*[\"'`;]|^\s*\)|--\s*>")


def tag_payload_contexts(payload: str) -> set[str]:
    tags: set[str] = set()
    if _TAG_BREAK_RE.search(payload) or "<script" in payload.lower():
        tags.add("html")
        tags.add("comment")
    if _DQ_BREAK_RE.search(payload):
        tags.add("attr-dq")
    if _SQ_BREAK_RE.search(payload):
        tags.add("attr-sq")
    if _UQ_BREAK_RE.match(payload):
        tags.add("attr-uq")
    if _URI_RE.match(payload):
        tags.add("uri")
    if _JS_BREAK_RE.match(payload) or payload.strip().startswith(("'", '"', "`")):
        tags.add("script")
    if not tags:
        tags.add("unknown")
    return tags

