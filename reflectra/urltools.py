"""
reflectra.urltools
--------------------
Shared representation of "one injectable point on one URL" so the probe
phase and the confirmation phase inject into exactly the same set of
locations (query params, fragment params, or a synthetic param when the
URL has neither).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit


@dataclass(frozen=True)
class ParamPoint:
    base_url: str
    location: str  # "query" | "fragment" | "fragment-raw" | "synthetic"
    param: str

    def render(self, value: str) -> str:
        scheme, netloc, path, query_string, fragment = urlsplit(self.base_url)
        scheme = scheme or "http"

        if self.location == "query":
            params = parse_qs(query_string, keep_blank_values=True)
            params[self.param] = [value]
            new_query = urlencode(params, doseq=True)
            return urlunsplit((scheme, netloc, path, new_query, fragment))

        if self.location == "fragment":
            params = parse_qs(fragment, keep_blank_values=True)
            params[self.param] = [value]
            new_fragment = urlencode(params, doseq=True)
            return urlunsplit((scheme, netloc, path, query_string, new_fragment))

        if self.location == "fragment-raw":
            return urlunsplit((scheme, netloc, path, query_string, value))

        if self.location == "synthetic":
            new_query = urlencode({self.param: value})
            return urlunsplit((scheme, netloc, path, new_query, fragment))

        raise ValueError(f"unknown location: {self.location}")


def injection_points(url: str) -> list[ParamPoint]:
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    points: list[ParamPoint] = []

    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params:
        points.append(ParamPoint(url, "query", key))

    if fragment:
        if "=" in fragment:
            frag_params = parse_qs(fragment, keep_blank_values=True)
            for key in frag_params:
                points.append(ParamPoint(url, "fragment", key))
        else:
            points.append(ParamPoint(url, "fragment-raw", "_frag"))

    if not points:
        points.append(ParamPoint(url, "synthetic", "test"))

    return points
