"""
tests/test_unit.py
--------------------
Pure-Python unit tests. No network calls, no Selenium, no Chrome. Runnable
anywhere Python + the package deps are installed.

Run: python -m pytest tests/test_unit.py -v
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reflectra.context import classify_reflection, tag_payload_contexts, make_marker
from reflectra.models import ProbeState
from reflectra.planner import select_for_point, plan_tasks, FALLBACK_STATES
from reflectra.probe import ProbeResult
from reflectra.models import ReflectionResult
from reflectra.urltools import injection_points, ParamPoint
from reflectra.sinks import find_reachable_sinks
import logging


def _logger():
    lg = logging.getLogger("test")
    lg.addHandler(logging.NullHandler())
    return lg


# --------------------------------------------------------------------------- #
# urltools: parameter handling
# --------------------------------------------------------------------------- #

def test_injection_points_multiple_query_params_independent():
    pts = injection_points("https://target.tld/search?page=1&sort=asc&filter=x")
    assert [p.param for p in pts] == ["page", "sort", "filter"]


def test_injection_points_preserves_unrelated_params_on_render():
    pts = injection_points("https://target.tld/search?page=1&sort=asc&filter=x")
    rendered = pts[1].render("PAYLOAD")  # sort=PAYLOAD, others untouched
    assert "page=1" in rendered
    assert "filter=x" in rendered
    assert "sort=PAYLOAD" in rendered


def test_injection_points_empty_value_preserved_as_point():
    pts = injection_points("https://target.tld/x?q=")
    assert len(pts) == 1
    assert pts[0].param == "q"


def test_injection_points_no_params_creates_synthetic():
    pts = injection_points("https://target.tld/page")
    assert len(pts) == 1
    assert pts[0].location == "synthetic"


def test_injection_points_fragment_query_style():
    pts = injection_points("https://target.tld/app#/route?id=5")
    assert any(p.location == "fragment" for p in pts)


def test_injection_points_fragment_raw():
    pts = injection_points("https://target.tld/app#section1")
    assert any(p.location == "fragment-raw" for p in pts)


def test_param_point_render_url_encodes_payload():
    pt = ParamPoint("https://target.tld/x?q=1", "query", "q")
    rendered = pt.render("<script>alert(1)</script>")
    assert "<script>" not in rendered  # must be percent-encoded
    assert "%3Cscript%3E" in rendered or "script" in rendered


# --------------------------------------------------------------------------- #
# context: reflection classification
# --------------------------------------------------------------------------- #

def test_classify_reflection_html_context():
    marker = make_marker()
    body = f"<html><body><p>hello {marker}</p></body></html>"
    r = classify_reflection(body, marker)
    assert r.state == ProbeState.REFLECTED
    assert "html" in r.contexts


def test_classify_reflection_attribute_dq():
    marker = make_marker()
    body = f'<input value="{marker}">'
    r = classify_reflection(body, marker)
    assert "attr-dq" in r.contexts


def test_classify_reflection_script_block():
    marker = make_marker()
    body = f'<script>var x = "{marker}";</script>'
    r = classify_reflection(body, marker)
    assert "script" in r.contexts


def test_classify_reflection_not_reflected_is_explicit_state():
    marker = make_marker()
    body = "<html>nothing here</html>"
    r = classify_reflection(body, marker)
    assert r.state == ProbeState.NOT_REFLECTED
    assert not r.reflected


def test_classify_reflection_never_returns_timeout_or_connection_states():
    """classify_reflection has no concept of network failure -- only
    REFLECTED / NOT_REFLECTED / AMBIGUOUS may come out of it."""
    marker = make_marker()
    r1 = classify_reflection("no marker", marker)
    r2 = classify_reflection(f"<div>{marker}<div", marker)  # malformed tag -> ambiguous-ish
    for r in (r1, r2):
        assert r.state not in (ProbeState.TIMEOUT, ProbeState.CONNECTION_ERROR, ProbeState.HTTP_ERROR)


# --------------------------------------------------------------------------- #
# context: payload tagging
# --------------------------------------------------------------------------- #

def test_tag_payload_script_context():
    tags = tag_payload_contexts("'-alert(1)-'")
    assert "script" in tags


def test_tag_payload_html_context():
    tags = tag_payload_contexts("<script>alert(1)</script>")
    assert "html" in tags


def test_tag_payload_uri_context():
    tags = tag_payload_contexts("javascript:alert(1)")
    assert "uri" in tags


def test_tag_payload_never_returns_empty():
    for p in ["", "plain text", "1234", "SELECT * FROM x"]:
        tags = tag_payload_contexts(p)
        assert len(tags) > 0  # always at least {"unknown"}


# --------------------------------------------------------------------------- #
# planner: THE critical regression-fix behavior
# --------------------------------------------------------------------------- #

def test_select_for_point_reorders_not_filters_when_no_cap():
    payloads = ["<script>alert(1)</script>", "javascript:alert(1)", "plain"]
    contexts = {p: frozenset(tag_payload_contexts(p)) for p in payloads}
    selected = select_for_point(payloads, contexts, {"uri"}, max_payloads=None)
    # nothing dropped -- just reordered so uri-matching comes first
    assert set(selected) == set(payloads)
    assert selected[0] == "javascript:alert(1)"


def test_select_for_point_respects_explicit_cap_only():
    payloads = [f"p{i}" for i in range(10)]
    contexts = {p: frozenset({"unknown"}) for p in payloads}
    selected = select_for_point(payloads, contexts, {"html"}, max_payloads=3)
    assert len(selected) == 3


def test_plan_tasks_fallback_states_get_full_payload_list():
    """The core regression-fix requirement: TIMEOUT/CONNECTION_ERROR/HTTP_ERROR
    must never reduce payload coverage below the full original list."""
    payloads = [f"payload{i}" for i in range(50)]
    point = ParamPoint("https://target.tld/x?q=1", "query", "q")

    for bad_state in FALLBACK_STATES:
        probe_results = {
            "https://target.tld/x?q=1": [
                ProbeResult(point, ReflectionResult(marker="m", state=bad_state))
            ]
        }
        tasks, stats = plan_tasks(probe_results, payloads, max_payloads_per_point=5, skip_unreflected=False, logger=_logger())
        # even though max_payloads_per_point=5, a probe-failure point must
        # still get the FULL 50-payload list -- the cap only applies to
        # confidently-classified REFLECTED points.
        assert len(tasks) == 50, f"state={bad_state} only produced {len(tasks)} tasks, expected 50 (full fallback)"


def test_plan_tasks_ambiguous_gets_full_payload_list():
    payloads = [f"payload{i}" for i in range(30)]
    point = ParamPoint("https://target.tld/x?q=1", "query", "q")
    probe_results = {
        "https://target.tld/x?q=1": [
            ProbeResult(point, ReflectionResult(marker="m", state=ProbeState.AMBIGUOUS, contexts={"unknown"}))
        ]
    }
    tasks, stats = plan_tasks(probe_results, payloads, max_payloads_per_point=5, skip_unreflected=False, logger=_logger())
    assert len(tasks) == 30


def test_plan_tasks_reflected_context_respects_cap():
    payloads = ["<script>alert(1)</script>"] + [f"noise{i}" for i in range(30)]
    point = ParamPoint("https://target.tld/x?q=1", "query", "q")
    probe_results = {
        "https://target.tld/x?q=1": [
            ProbeResult(point, ReflectionResult(marker="m", state=ProbeState.REFLECTED, contexts={"html"}))
        ]
    }
    tasks, stats = plan_tasks(probe_results, payloads, max_payloads_per_point=5, skip_unreflected=False, logger=_logger())
    assert len(tasks) == 5
    # the html-matching payload must be prioritized to the front, not dropped
    assert tasks[0].payload == "<script>alert(1)</script>"


def test_plan_tasks_reflected_no_cap_keeps_everything():
    payloads = [f"payload{i}" for i in range(2605)]  # v1 payload-count parity
    point = ParamPoint("https://target.tld/x?q=1", "query", "q")
    probe_results = {
        "https://target.tld/x?q=1": [
            ProbeResult(point, ReflectionResult(marker="m", state=ProbeState.REFLECTED, contexts={"html"}))
        ]
    }
    tasks, stats = plan_tasks(probe_results, payloads, max_payloads_per_point=None, skip_unreflected=False, logger=_logger())
    assert len(tasks) == 2605  # zero payloads lost -- full v1-equivalent coverage


# --------------------------------------------------------------------------- #
# sinks: static analysis
# --------------------------------------------------------------------------- #

def test_find_reachable_sinks_detects_innerHTML():
    marker = "rfxMARK123"
    source = f'<script>document.getElementById("x").innerHTML = "{marker}";</script>'
    hits = find_reachable_sinks(source, marker)
    assert any(h.sink == "innerHTML" for h in hits)


def test_find_reachable_sinks_no_marker_no_hits():
    hits = find_reachable_sinks("<script>el.innerHTML = 'safe';</script>", "rfxNOTPRESENT")
    assert hits == []


# --------------------------------------------------------------------------- #
# browser: stop-on-first-confirmed (additive, opt-in, default-off)
# --------------------------------------------------------------------------- #

def test_stop_on_first_confirmed_defaults_to_off():
    from reflectra.browser import BrowserConfirmationEngine
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.0, logger=_logger())
    assert engine.stop_on_first_confirmed is False
    assert not engine._stop_event.is_set()


def test_stop_event_set_only_on_confirmed_kind():
    from reflectra.browser import BrowserConfirmationEngine, Task
    from reflectra.models import FindingKind
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.0, logger=_logger(), stop_on_first_confirmed=True)
    point = ParamPoint("http://t/x?q=1", "query", "q")

    # A sink-reachable lead must NOT trip the stop event.
    engine._record(FindingKind.SINK_REACHABLE_LEAD, Task(point, "p", "html"), "http://t/x?q=p", detail="d")
    assert not engine._stop_event.is_set()

    # A confirmed finding must.
    engine._record(FindingKind.CONFIRMED_XSS, Task(point, "p2", "html"), "http://t/x?q=p2", dialog_text="1")
    assert engine._stop_event.is_set()


def test_confirm_one_skips_when_stop_event_already_set():
    """With stop_on_first_confirmed=True and the event already tripped,
    confirm_one must return immediately without touching the driver pool
    (proves 'attack stop' behavior at the unit level without needing Chrome)."""
    from reflectra.browser import BrowserConfirmationEngine, Task
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.0, logger=_logger(), stop_on_first_confirmed=True)
    engine._stop_event.set()
    point = ParamPoint("http://t/x?q=1", "query", "q")
    engine.confirm_one(Task(point, "irrelevant", "html"))
    # driver pool must never have been touched -- no drivers created
    assert engine.driver_pool._all_drivers == []
    assert len(engine.findings) == 0


def test_on_finding_callback_invoked():
    from reflectra.browser import BrowserConfirmationEngine, Task
    from reflectra.models import FindingKind
    seen = []
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.0, logger=_logger(), on_finding=seen.append)
    point = ParamPoint("http://t/x?q=1", "query", "q")
    engine._record(FindingKind.CONFIRMED_XSS, Task(point, "p", "html"), "http://t/x?q=p", dialog_text="1")
    assert len(seen) == 1
    assert seen[0].kind == FindingKind.CONFIRMED_XSS


def test_on_finding_callback_exception_does_not_break_scan():
    """A broken UI callback must never take down the scan."""
    from reflectra.browser import BrowserConfirmationEngine, Task
    from reflectra.models import FindingKind

    def bad_callback(f):
        raise RuntimeError("boom")

    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.0, logger=_logger(), on_finding=bad_callback)
    point = ParamPoint("http://t/x?q=1", "query", "q")
    engine._record(FindingKind.CONFIRMED_XSS, Task(point, "p", "html"), "http://t/x?q=p", dialog_text="1")
    assert len(engine.findings) == 1  # recorded despite the callback raising


def test_max_confirmed_stops_only_after_reaching_threshold():
    """The core new behavior: stop after N confirmed, not after 1, when
    max_confirmed is set to something other than 1."""
    from reflectra.browser import BrowserConfirmationEngine, Task
    from reflectra.models import FindingKind
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.0, logger=_logger(), max_confirmed=5)
    point = ParamPoint("http://t/x?q=1", "query", "q")

    for i in range(4):
        engine._record(FindingKind.CONFIRMED_XSS, Task(point, f"p{i}", "html"), f"http://t/x?q=p{i}", dialog_text="1")
        assert not engine._stop_event.is_set(), f"stopped early after {i+1} confirmed, expected threshold 5"

    engine._record(FindingKind.CONFIRMED_XSS, Task(point, "p5", "html"), "http://t/x?q=p5", dialog_text="1")
    assert engine._stop_event.is_set()
    assert engine._confirmed_count == 5


def test_stop_on_first_confirmed_flag_is_alias_for_max_confirmed_1():
    from reflectra.browser import BrowserConfirmationEngine
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.0, logger=_logger(), stop_on_first_confirmed=True)
    assert engine.max_confirmed == 1


def test_max_confirmed_none_by_default_never_stops():
    from reflectra.browser import BrowserConfirmationEngine, Task
    from reflectra.models import FindingKind
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.0, logger=_logger())
    point = ParamPoint("http://t/x?q=1", "query", "q")
    for i in range(20):
        engine._record(FindingKind.CONFIRMED_XSS, Task(point, f"p{i}", "html"), f"http://t/x?q=p{i}", dialog_text="1")
    assert not engine._stop_event.is_set()  # unbounded by default -- unaffected caller


# --------------------------------------------------------------------------- #
# naming: auto report path generation
# --------------------------------------------------------------------------- #

def test_auto_report_path_creates_reports_dir(tmp_path, monkeypatch):
    from reflectra import naming
    monkeypatch.chdir(tmp_path)
    path = naming.auto_report_path("https://target.tld/search?q=1")
    assert os.path.isdir("reports")
    assert path.startswith("reports" + os.sep)
    assert path.endswith(".html")
    assert "target.tld" in path


def test_auto_report_path_slugifies_unsafe_chars(tmp_path, monkeypatch):
    from reflectra import naming
    monkeypatch.chdir(tmp_path)
    path = naming.auto_report_path("https://sub.target.tld:8443/app?x=1")
    fname = os.path.basename(path)
    assert ":" not in fname
    assert "/" not in fname
    assert "sub.target.tld" in fname


def test_auto_report_path_handles_multi_target_label(tmp_path, monkeypatch):
    from reflectra import naming
    monkeypatch.chdir(tmp_path)
    path = naming.auto_report_path("https://a.tld/x?y=1, https://b.tld/x?y=1")
    assert "a.tld" in os.path.basename(path)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
