"""
tests/test_legacy_engine_compatibility.py
--------------------------------------------
Browser integration tests. These require a real Chrome/Chromium binary
reachable by webdriver-manager. They are SKIPPED (not faked, not silently
passed) when no browser is available -- see `_chrome_available()` below.

In the environment this project was upgraded in, no Chrome/Chromium binary
could be installed (sandboxed container, package manager only offered a
broken snap stub with no network path to a real installer). These tests
were written, and verified to correctly SKIP with a clear reason in that
environment -- they were NOT executed against a real browser as part of
this delivery. Run them yourself on a machine with Chrome/Chromium
installed before trusting the browser-confirmation path in production.

Run: python -m pytest tests/test_legacy_engine_compatibility.py -v
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import pytest

from reflectra.browser import BrowserConfirmationEngine, Task
from reflectra.urltools import ParamPoint, injection_points
from fixtures.fixture_server import ThreadingHTTPServer, FixtureHandler

PORT = 8124
BASE = f"http://127.0.0.1:{PORT}"


def _chrome_available() -> bool:
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        if shutil.which(name):
            return True
    return False


requires_chrome = pytest.mark.skipif(
    not _chrome_available(),
    reason="No Chrome/Chromium binary found on PATH -- browser integration tests skipped. "
           "Install Chrome/Chromium and re-run to exercise the detection core.",
)


def _logger():
    lg = logging.getLogger("test-compat")
    lg.setLevel(logging.DEBUG)
    lg.addHandler(logging.NullHandler())
    return lg


@pytest.fixture(scope="module")
def fixture_server():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    yield server
    server.shutdown()
    server.server_close()


# --------------------------------------------------------------------------- #
# 1. Same target URL produces the same injection points (no browser needed,
#    but included here to keep the compatibility checklist in one file).
# --------------------------------------------------------------------------- #

def test_01_injection_points_are_deterministic():
    a = injection_points(f"{BASE}/multi?a=1&b=2&c=3")
    b = injection_points(f"{BASE}/multi?a=1&b=2&c=3")
    assert [p.param for p in a] == [p.param for p in b]


# --------------------------------------------------------------------------- #
# 2. Same payload is encoded into the same parameter correctly.
# --------------------------------------------------------------------------- #

def test_02_payload_encoded_into_correct_parameter_only():
    pts = injection_points(f"{BASE}/multi?a=1&b=2&c=3")
    b_point = [p for p in pts if p.param == "b"][0]
    rendered = b_point.render("<script>alert(1)</script>")
    assert "a=1" in rendered and "c=3" in rendered
    assert "b=" in rendered


# --------------------------------------------------------------------------- #
# 3-8: require a real browser.
# --------------------------------------------------------------------------- #

@requires_chrome
def test_03_payload_reaches_chrome_and_fires_alert(fixture_server):
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=3.0, logger=_logger())
    point = ParamPoint(f"{BASE}/html?v=x", "query", "v")
    task = Task(point, "<script>alert('reflectra')</script>", context="html")
    engine.confirm_one(task)
    engine.driver_pool.shutdown()
    confirmed = [f for f in engine.findings if f.kind.value == "CONFIRMED_XSS"]
    assert len(confirmed) == 1
    assert confirmed[0].dialog_text == "reflectra"


@requires_chrome
def test_04_confirm_dialog_recognized(fixture_server):
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=3.0, logger=_logger())
    point = ParamPoint(f"{BASE}/html?v=x", "query", "v")
    task = Task(point, "<script>confirm('c')</script>", context="html")
    engine.confirm_one(task)
    engine.driver_pool.shutdown()
    assert any(f.kind.value == "CONFIRMED_XSS" for f in engine.findings)


@requires_chrome
def test_05_prompt_dialog_recognized(fixture_server):
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=3.0, logger=_logger())
    point = ParamPoint(f"{BASE}/html?v=x", "query", "v")
    task = Task(point, "<script>prompt('p')</script>", context="html")
    engine.confirm_one(task)
    engine.driver_pool.shutdown()
    assert any(f.kind.value == "CONFIRMED_XSS" for f in engine.findings)


@requires_chrome
def test_06_no_dialog_does_not_produce_false_confirmed(fixture_server):
    """/safe HTML-escapes output -- payload must NOT confirm."""
    engine = BrowserConfirmationEngine(threads=1, dialog_timeout=1.5, logger=_logger(), probe_sinks=False)
    point = ParamPoint(f"{BASE}/safe?v=x", "query", "v")
    task = Task(point, "<script>alert('should-not-fire')</script>", context="html")
    engine.confirm_one(task)
    engine.driver_pool.shutdown()
    assert not any(f.kind.value == "CONFIRMED_XSS" for f in engine.findings)


@requires_chrome
def test_07_one_worker_failure_does_not_kill_other_tasks(fixture_server):
    """A payload targeting an unroutable host must produce an ERROR finding
    and NOT prevent other queued tasks from completing."""
    engine = BrowserConfirmationEngine(threads=2, dialog_timeout=2.0, logger=_logger())
    bad_point = ParamPoint("http://192.0.2.1/html?v=x", "query", "v")
    good_point = ParamPoint(f"{BASE}/html?v=x", "query", "v")
    tasks = [
        Task(bad_point, "<script>alert(1)</script>", "html"),
        Task(good_point, "<script>alert('ok')</script>", "html"),
    ]
    engine.run(tasks)
    kinds = {f.kind.value for f in engine.findings}
    assert "CONFIRMED_XSS" in kinds  # the good task still completed
    assert engine.stats.total_errors >= 1 or "ERROR" in kinds  # the bad task was recorded as error, not silently dropped


@requires_chrome
def test_08_driver_cleanup_releases_all_drivers(fixture_server):
    engine = BrowserConfirmationEngine(threads=2, dialog_timeout=1.5, logger=_logger())
    point = ParamPoint(f"{BASE}/html?v=x", "query", "v")
    engine.run([Task(point, "<script>alert(1)</script>", "html") for _ in range(3)])
    assert engine.driver_pool._pool.qsize() == 0  # shutdown() quits and clears; nothing left pooled
    assert engine.driver_pool._all_drivers == []


# --------------------------------------------------------------------------- #
# 9. Threaded scanning remains stable under concurrent load.
# --------------------------------------------------------------------------- #

@requires_chrome
def test_09_threaded_scan_stable_under_load(fixture_server):
    engine = BrowserConfirmationEngine(threads=4, dialog_timeout=2.0, logger=_logger())
    point = ParamPoint(f"{BASE}/html?v=x", "query", "v")
    tasks = [Task(point, "<script>alert(1)</script>", "html") for _ in range(12)]
    engine.run(tasks)
    confirmed = [f for f in engine.findings if f.kind.value == "CONFIRMED_XSS"]
    assert len(confirmed) == 12  # every task completed, no deadlock/race dropped results


# --------------------------------------------------------------------------- #
# 10. v2 does not alter original payload semantics (payload string sent
#     verbatim, not mutated by the optimization layer).
# --------------------------------------------------------------------------- #

def test_10_payload_semantics_unaltered_by_point_render():
    pt = ParamPoint(f"{BASE}/html?v=x", "query", "v")
    payload = "<script>alert(String.fromCharCode(88,83,83))</script>"
    rendered = pt.render(payload)
    from urllib.parse import parse_qs, urlsplit
    decoded = parse_qs(urlsplit(rendered).query)["v"][0]
    assert decoded == payload  # round-trips exactly, nothing added/stripped/mutated


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
