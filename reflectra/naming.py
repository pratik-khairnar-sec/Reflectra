"""
reflectra.naming
-------------------
Automatic report file naming so a report is always saved somewhere sane
without the user having to specify a path. Reports go into ./reports/
(created if missing), named after the target and a timestamp, e.g.:

    reports/reflectra_target-tld_20260929-141501.html

Purely a naming/filesystem convenience -- no detection/probing logic here.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from urllib.parse import urlsplit

REPORTS_DIR = "reports"


def _slugify_target(target_label: str) -> str:
    """Turn a target URL (or comma-joined list of them) into a short,
    filesystem-safe slug based on the first target's hostname."""
    first = target_label.split(",")[0].strip() if target_label else ""
    host = ""
    try:
        host = urlsplit(first).netloc or urlsplit(first).path
    except ValueError:
        host = first
    host = host.split("@")[-1]  # strip any userinfo
    host = host.split(":")[0]   # strip port
    slug = re.sub(r"[^a-zA-Z0-9.-]+", "-", host).strip("-")
    return slug or "target"


def auto_report_path(target_label: str, ext: str = ".html") -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    slug = _slugify_target(target_label)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"reflectra_{slug}_{timestamp}{ext}"
    return os.path.join(REPORTS_DIR, filename)
