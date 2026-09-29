"""
reflectra.engine
------------------
Orchestration only. No detection logic lives here -- that is
reflectra.browser (the preserved original engine). This module wires:

    probe.probe_target()          (phase 1: reflection probing)
        -> planner.plan_tasks()    (fallback-safe payload/task selection)
            -> browser.BrowserConfirmationEngine.run()  (phase 2: original detection core)

kept separate so the orchestration/optimization layer can be modified or
disabled (--no-context-filter) without touching the detection core at all.
"""

from __future__ import annotations

import logging

from .browser import BrowserConfirmationEngine, Task, VERSION  # noqa: F401  (VERSION re-exported)
from .models import ProbeState, ReflectionResult
from .planner import PlanStats, plan_tasks
from .probe import ProbeResult
from .urltools import injection_points


def brute_force_probe_results(targets: list[str]) -> dict[str, list[ProbeResult]]:
    """Used with --no-context-filter: synthesize AMBIGUOUS probe results for
    every injection point so the planner runs the FULL payload list against
    every point, unfiltered -- i.e. reproduces v1's exhaustive behavior
    exactly, through the same planner fallback path used for real probe
    failures (no separate code path to keep in sync)."""
    results: dict[str, list[ProbeResult]] = {}
    for url in targets:
        results[url] = [
            ProbeResult(pt, ReflectionResult(marker="", state=ProbeState.AMBIGUOUS, contexts={"unknown"}))
            for pt in injection_points(url)
        ]
    return results
