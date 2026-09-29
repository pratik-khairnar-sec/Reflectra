"""
reflectra.planner
-------------------
Turns phase-1 probe results into the task list phase 2 (browser.py, the
original confirmation engine) actually runs.

This module is the enforcement point for the project's core safety rule:
context filtering is an optimization, never an authority. The mapping from
ProbeState to payload selection is:

    REFLECTED (context known)  -> prioritize context-matching payloads first,
                                    but still include the rest, capped by
                                    --max-payloads-per-point (coverage first,
                                    ordering second -- see select_for_point)
    AMBIGUOUS                   -> run the full/broad payload set for this point
    NOT_REFLECTED                -> optionally sample a small generic set
                                    (server-side probe can't see pure client-
                                    side DOM sinks, so "not reflected" here
                                    does not mean "not vulnerable")
    TIMEOUT / CONNECTION_ERROR /
    HTTP_ERROR                   -> MUST fall back to the full original
                                    payload list for this point, exactly as
                                    if context filtering had never run. A
                                    probe failure is not evidence.

Note what changed from the pre-regression-fix version: the old
`select_payloads()` in context.py *filtered out* non-matching payloads
when a context was confidently detected. Here, `select_for_point()`
*reorders* instead of filtering when confidence is high, and only ever
truncates via the explicit `--max-payloads-per-point` cap the user
controls -- so a wrong context guess can cost ordering/priority, never
outright silently drop the one payload that would have worked, unless the
user has explicitly opted into a cap smaller than the full list.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .browser import Task
from .context import tag_payload_contexts
from .models import ProbeState
from .probe import ProbeResult
from .urltools import ParamPoint

# States that carry zero evidence about vulnerability -- context filtering
# must never be applied for these; full payload list is used verbatim.
FALLBACK_STATES = {ProbeState.TIMEOUT, ProbeState.CONNECTION_ERROR, ProbeState.HTTP_ERROR}

# Default sample size for NOT_REFLECTED points (pure DOM XSS can't be seen
# by a server-side probe at all, so we still try a slice, not zero).
DEFAULT_UNREFLECTED_SAMPLE = 25


@dataclass
class PlanStats:
    total_points: int = 0
    reflected_points: int = 0
    ambiguous_points: int = 0
    not_reflected_points: int = 0
    fallback_points: int = 0  # TIMEOUT/CONNECTION_ERROR/HTTP_ERROR
    total_tasks: int = 0
    full_coverage_tasks: int = 0  # tasks run without any context narrowing


def select_for_point(
    all_payloads: list[str],
    payload_contexts: dict[str, frozenset],
    detected_contexts: set[str],
    max_payloads: int | None,
) -> list[str]:
    """Reorder `all_payloads` so context-matching entries come first,
    then return up to `max_payloads` of them. Coverage over aggression:
    if max_payloads is None or >= len(all_payloads), NOTHING is dropped --
    only reordered. Only an explicit, smaller cap can shrink the list."""
    if not detected_contexts or "unknown" in detected_contexts:
        ordered = list(all_payloads)
    else:
        matching = [p for p in all_payloads if payload_contexts[p] & detected_contexts]
        rest = [p for p in all_payloads if not (payload_contexts[p] & detected_contexts)]
        ordered = matching + rest  # matching payloads first, but rest is NOT discarded

    if max_payloads is not None and max_payloads > 0 and max_payloads < len(ordered):
        return ordered[:max_payloads]
    return ordered


def plan_tasks(
    probe_results: dict[str, list[ProbeResult]],
    payloads: list[str],
    max_payloads_per_point: int | None,
    skip_unreflected: bool,
    logger: logging.Logger,
) -> tuple[list[Task], PlanStats]:
    stats = PlanStats()
    payload_contexts = {p: frozenset(tag_payload_contexts(p)) for p in payloads}
    tasks: list[Task] = []

    for target_url, results in probe_results.items():
        for pr in results:
            stats.total_points += 1
            state = pr.reflection.state

            if state in FALLBACK_STATES:
                # Probe gave us nothing usable -- run the ORIGINAL full payload
                # list against this point, unfiltered, exactly as v1 would have.
                stats.fallback_points += 1
                stats.full_coverage_tasks += len(payloads)
                for p in payloads:
                    tasks.append(Task(pr.point, p, context=f"fallback:{state.value}"))
                continue

            if state == ProbeState.NOT_REFLECTED:
                stats.not_reflected_points += 1
                if skip_unreflected:
                    continue
                sample = payloads[: max_payloads_per_point or DEFAULT_UNREFLECTED_SAMPLE]
                for p in sample:
                    tasks.append(Task(pr.point, p, context="unreflected-dom-probe"))
                continue

            if state == ProbeState.AMBIGUOUS:
                stats.ambiguous_points += 1
                # Ambiguous means "reflected but we don't trust the context
                # classification" -- run the full list, same as a fallback point.
                stats.full_coverage_tasks += len(payloads)
                for p in payloads:
                    tasks.append(Task(pr.point, p, context="ambiguous"))
                continue

            # state == REFLECTED with a confidently classified context.
            stats.reflected_points += 1
            selected = select_for_point(payloads, payload_contexts, pr.reflection.contexts, max_payloads_per_point)
            ctx_label = "/".join(sorted(pr.reflection.contexts))
            for p in selected:
                tasks.append(Task(pr.point, p, context=ctx_label))

    stats.total_tasks = len(tasks)
    logger.info(
        f"[i] Planner: {stats.reflected_points} reflected, {stats.ambiguous_points} ambiguous, "
        f"{stats.not_reflected_points} not-reflected, {stats.fallback_points} probe-failed "
        f"(full-coverage fallback) point(s) -> {stats.total_tasks} browser task(s)"
    )
    return tasks, stats
