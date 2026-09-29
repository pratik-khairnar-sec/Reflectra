"""
reflectra.models
------------------
Shared enums and small dataclasses used across the probe, planner, and
engine modules. Centralized here so probe results and planner decisions
speak a common, explicit vocabulary instead of overloading booleans.

The core rule this module encodes: reflection-probe outcomes are NOT a
binary "reflected / not reflected". A probe can fail for reasons that have
nothing to do with whether the parameter is vulnerable (timeout, connection
reset, HTTP error). Only ProbeState.REFLECTED is treated as positive
evidence for context-based payload filtering. Every other state must fall
back to full/broad payload coverage rather than being silently treated as
"not vulnerable".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ProbeState(str, Enum):
    REFLECTED = "REFLECTED"
    NOT_REFLECTED = "NOT_REFLECTED"
    AMBIGUOUS = "AMBIGUOUS"
    TIMEOUT = "TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    HTTP_ERROR = "HTTP_ERROR"


class FindingKind(str, Enum):
    CONFIRMED_XSS = "CONFIRMED_XSS"
    SINK_REACHABLE_LEAD = "SINK_REACHABLE_LEAD"
    BLIND_INJECTION = "BLIND_INJECTION"
    ERROR = "ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class ReflectionResult:
    marker: str
    state: ProbeState
    contexts: set[str] = field(default_factory=set)
    occurrences: int = 0
    html_encoded: bool = False
    js_string_escaped: bool = False
    detail: str = ""

    @property
    def reflected(self) -> bool:
        return self.state == ProbeState.REFLECTED


@dataclass
class Finding:
    kind: FindingKind
    target_url: str
    payload: str
    injected_url: str
    context: str = ""
    dialog_text: str = ""
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
