"""
reflectra.probe
-----------------
Phase 1 of a scan: cheap plain-HTTP reflection probing.

For every injectable point (query param / fragment param) on a target, send
a unique marker via `requests` and classify the outcome as one of:

    REFLECTED          marker found, context classified           -> planner may prioritize
    AMBIGUOUS           marker found, context unclear               -> planner runs broad coverage
    NOT_REFLECTED       request succeeded, marker genuinely absent   -> planner may still sample
    TIMEOUT              request timed out                            -> planner MUST fall back to full coverage
    CONNECTION_ERROR     connection refused/reset/DNS failure         -> planner MUST fall back to full coverage
    HTTP_ERROR            request completed but server returned 5xx    -> planner MUST fall back to full coverage

The critical property: TIMEOUT / CONNECTION_ERROR / HTTP_ERROR are never
conflated with NOT_REFLECTED. A probe failure carries zero evidence about
whether the parameter is vulnerable -- it only means phase 1 couldn't get
an answer, so phase 2 must not be starved of candidates because of it.

Auth support: --cookie / --header are applied to the same
`requests.Session` used here AND propagated into the browser engine in
browser.py, so authenticated coverage is consistent between phases.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import requests
from requests.exceptions import ConnectionError as ReqConnectionError
from requests.exceptions import RequestException, Timeout

from .context import classify_reflection, make_marker
from .models import ProbeState, ReflectionResult
from .urltools import ParamPoint, injection_points


@dataclass
class ProbeResult:
    point: ParamPoint
    reflection: ReflectionResult


def build_session(cookies: Optional[str], headers: Optional[list[str]], insecure: bool) -> requests.Session:
    session = requests.Session()
    session.verify = not insecure

    if cookies:
        for pair in cookies.split(";"):
            pair = pair.strip()
            if not pair or "=" not in pair:
                continue
            k, v = pair.split("=", 1)
            session.cookies.set(k.strip(), v.strip())

    if headers:
        for h in headers:
            if ":" not in h:
                continue
            k, v = h.split(":", 1)
            session.headers[k.strip()] = v.strip()

    session.headers.setdefault(
        "User-Agent",
        "Reflectra/2.0 (+https://github.com/pratik-khairnar-sec/Reflectra; authorized-security-testing)",
    )
    return session


def probe_target(
    url: str,
    session: requests.Session,
    logger: logging.Logger,
    request_timeout: float = 10.0,
) -> list[ProbeResult]:
    """Probe every injection point on `url`. Always returns exactly one
    ProbeResult per point, including points where the probe request itself
    failed -- callers must inspect `.reflection.state`, never assume
    presence in this list implies REFLECTED or NOT_REFLECTED."""
    results: list[ProbeResult] = []

    for point in injection_points(url):
        marker = make_marker()
        probe_url = point.render(marker)
        try:
            resp = session.get(probe_url, timeout=request_timeout, allow_redirects=True)
        except Timeout:
            logger.debug(f"[probe] TIMEOUT on {probe_url}")
            results.append(ProbeResult(point, ReflectionResult(marker, ProbeState.TIMEOUT)))
            continue
        except ReqConnectionError as exc:
            logger.debug(f"[probe] CONNECTION_ERROR on {probe_url}: {exc}")
            results.append(ProbeResult(point, ReflectionResult(marker, ProbeState.CONNECTION_ERROR)))
            continue
        except RequestException as exc:
            logger.debug(f"[probe] request failed on {probe_url}: {exc}")
            results.append(ProbeResult(point, ReflectionResult(marker, ProbeState.CONNECTION_ERROR, detail=str(exc))))
            continue

        if resp.status_code >= 500:
            logger.debug(f"[probe] HTTP_ERROR {resp.status_code} on {probe_url}")
            results.append(
                ProbeResult(point, ReflectionResult(marker, ProbeState.HTTP_ERROR, detail=f"HTTP {resp.status_code}"))
            )
            continue

        reflection = classify_reflection(resp.text, marker)
        results.append(ProbeResult(point, reflection))

    return results
