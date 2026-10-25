#!/usr/bin/env python3
"""
Reflectra-XSS
-----------
A focused, standalone Cross-Site Scripting (XSS) scanner.

Detection method: reflects each payload into every query-string parameter
(and URL fragment) of a target URL, renders the resulting page in a
headless Chrome instance, and confirms exploitation by catching a native
JavaScript dialog (alert/confirm/prompt) triggered by the injected payload.
This means it detects *actual* client-side execution rather than a naive
string-reflection match, which keeps the false-positive rate low.

Author: Pratik Khairnar
License: See LICENSE

Usage:
    python3 reflectra_xss.py --url "https://target.tld/search?q=test"
    python3 reflectra_xss.py --file urls.txt --threads 10 --output report.html

For authorized security testing and educational purposes only.
See README.md for the full legal disclaimer.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from queue import Empty, Queue
from urllib.parse import (
    parse_qs,
    urlencode,
    urlsplit,
    urlunsplit,
)

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # pragma: no cover
    print("[!] Missing dependency 'colorama'. Install with: pip install -r requirements.txt")
    sys.exit(1)

try:
    from selenium import webdriver
    from selenium.common.exceptions import (
        TimeoutException,
        UnexpectedAlertPresentException,
        WebDriverException,
    )
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:  # pragma: no cover
    print("[!] Missing Selenium/webdriver-manager dependency. Install with: pip install -r requirements.txt")
    sys.exit(1)


colorama_init(autoreset=True)

VERSION = "1.0.0"
DEFAULT_PAYLOAD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads", "xss.txt")

BANNER = f"""{Fore.CYAN}========================================
{Fore.GREEN}          Reflectra-XSS
{Fore.YELLOW}    Cross Site Scripting Scanner
{Fore.CYAN}            By Pratik Khairnar
========================================{Style.RESET_ALL}
{Fore.WHITE}         Version {VERSION}{Style.RESET_ALL}
"""


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("reflectra_xss")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = "%(asctime)s [%(levelname)s] %(message)s" if verbose else "%(message)s"
        handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
        logger.addHandler(handler)

    # Silence noisy third-party loggers unless verbose.
    logging.getLogger("WDM").setLevel(logging.ERROR if not verbose else logging.INFO)
    logging.getLogger("selenium").setLevel(logging.ERROR if not verbose else logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.ERROR if not verbose else logging.WARNING)

    return logger


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    target_url: str
    payload: str
    injected_url: str
    dialog_text: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


@dataclass
class ScanStats:
    total_requests: int = 0
    total_errors: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0

    @property
    def elapsed(self) -> float:
        end = self.end_time or time.time()
        return round(end - self.start_time, 2)


# --------------------------------------------------------------------------- #
# Payload / URL handling
# --------------------------------------------------------------------------- #

def load_payloads(payload_source: str, logger: logging.Logger) -> list[str]:
    """Load payloads from a file, or treat the argument as a single literal payload
    if it does not point to an existing file."""
    if os.path.isfile(payload_source):
        try:
            with open(payload_source, "r", encoding="utf-8", errors="ignore") as fh:
                payloads = [
                    line.rstrip("\n").rstrip("\r")
                    for line in fh
                    if line.strip() and not line.lstrip().startswith("#")
                ]
        except OSError as exc:
            logger.error(f"[!] Could not read payload file '{payload_source}': {exc}")
            sys.exit(1)

        if not payloads:
            logger.error(f"[!] Payload file '{payload_source}' is empty.")
            sys.exit(1)
        return payloads

    # Not a file path -> treat as a single ad-hoc payload string.
    return [payload_source]


def load_targets(args: argparse.Namespace, logger: logging.Logger) -> list[str]:
    targets: list[str] = []

    if args.url:
        targets.append(args.url.strip())

    if args.file:
        if not os.path.isfile(args.file):
            logger.error(f"[!] URL file not found: {args.file}")
            sys.exit(1)
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
                targets.extend(line.strip() for line in fh if line.strip())
        except OSError as exc:
            logger.error(f"[!] Could not read URL file '{args.file}': {exc}")
            sys.exit(1)

    # De-duplicate while preserving order.
    seen = set()
    deduped = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)

    if not deduped:
        logger.error("[!] No targets provided. Use --url or --file.")
        sys.exit(1)

    return deduped


def build_injection_urls(url: str, payload: str) -> list[str]:
    """Return every variant of `url` with `payload` injected into one query
    parameter (or the fragment) at a time. If the URL has no parameters or
    fragment, a synthetic `?test=` parameter is appended."""
    variants: list[str] = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    scheme = scheme or "http"

    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params:
        modified = query_params.copy()
        modified[key] = [payload]
        new_query = urlencode(modified, doseq=True)
        variants.append(urlunsplit((scheme, netloc, path, new_query, fragment)))

    if fragment:
        if "=" in fragment:
            frag_params = parse_qs(fragment, keep_blank_values=True)
            for key in frag_params:
                modified = frag_params.copy()
                modified[key] = [payload]
                new_fragment = urlencode(modified, doseq=True)
                variants.append(urlunsplit((scheme, netloc, path, query_string, new_fragment)))
        else:
            variants.append(urlunsplit((scheme, netloc, path, query_string, payload)))

    if not query_params and not fragment:
        variants.append(urlunsplit((scheme, netloc, path, urlencode({"test": payload}), fragment)))
        variants.append(urlunsplit((scheme, netloc, path, query_string, payload)))

    return variants


# --------------------------------------------------------------------------- #
# Browser driver pool
# --------------------------------------------------------------------------- #

class DriverPool:
    """Thread-safe pool of headless Chrome WebDriver instances, created lazily
    and reused across worker threads to avoid the cost of spinning up a new
    browser per request."""

    def __init__(self, logger: logging.Logger):
        self._pool: Queue = Queue()
        self._all_drivers: list = []
        self._lock = threading.Lock()
        self._logger = logger

    def _create_driver(self):
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-infobars")
        options.add_argument("--disable-notifications")
        options.add_argument("--disable-gpu")
        options.page_load_strategy = "eager"

        logging.getLogger("WDM").setLevel(logging.ERROR)
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(30)
        with self._lock:
            self._all_drivers.append(driver)
        return driver

    def acquire(self):
        try:
            return self._pool.get_nowait()
        except Empty:
            return self._create_driver()

    def release(self, driver) -> None:
        self._pool.put(driver)

    def shutdown(self) -> None:
        with self._lock:
            for driver in self._all_drivers:
                try:
                    driver.quit()
                except WebDriverException:
                    pass
            self._all_drivers.clear()


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class XSSScanner:
    def __init__(
        self,
        payloads: list[str],
        threads: int,
        timeout: float,
        logger: logging.Logger,
        verbose: bool = False,
    ):
        self.payloads = payloads
        self.threads = max(1, threads)
        self.timeout = timeout
        self.logger = logger
        self.verbose = verbose
        self.driver_pool = DriverPool(logger)
        self.findings: list[Finding] = []
        self.findings_lock = threading.Lock()
        self.stats = ScanStats()

    def _check_injection(self, target_url: str, payload: str) -> None:
        injection_urls = build_injection_urls(target_url, payload)
        if not injection_urls:
            return

        driver = self.driver_pool.acquire()
        try:
            for injected_url in injection_urls:
                try:
                    driver.get(injected_url)
                    with self.findings_lock:
                        self.stats.total_requests += 1

                    try:
                        alert = WebDriverWait(driver, self.timeout).until(EC.alert_is_present())
                        dialog_text = alert.text
                        alert.accept()

                        finding = Finding(
                            target_url=target_url,
                            payload=payload,
                            injected_url=injected_url,
                            dialog_text=dialog_text,
                        )
                        with self.findings_lock:
                            self.findings.append(finding)

                        print(
                            f"{Fore.GREEN}[+] VULNERABLE{Style.RESET_ALL} "
                            f"{Fore.CYAN}{injected_url}{Style.RESET_ALL} "
                            f"{Fore.YELLOW}(dialog: {dialog_text!r}){Style.RESET_ALL}"
                        )

                    except TimeoutException:
                        if self.verbose:
                            print(f"{Fore.RED}[-] Not vulnerable{Style.RESET_ALL} {injected_url}")

                except UnexpectedAlertPresentException:
                    # A dialog fired during navigation itself; treat as a hit.
                    try:
                        alert = driver.switch_to.alert
                        dialog_text = alert.text
                        alert.accept()
                        finding = Finding(
                            target_url=target_url,
                            payload=payload,
                            injected_url=injected_url,
                            dialog_text=dialog_text,
                        )
                        with self.findings_lock:
                            self.findings.append(finding)
                        print(
                            f"{Fore.GREEN}[+] VULNERABLE{Style.RESET_ALL} "
                            f"{Fore.CYAN}{injected_url}{Style.RESET_ALL} "
                            f"{Fore.YELLOW}(dialog: {dialog_text!r}){Style.RESET_ALL}"
                        )
                    except WebDriverException:
                        pass
                except WebDriverException as exc:
                    with self.findings_lock:
                        self.stats.total_errors += 1
                    self.logger.debug(f"[!] WebDriver error on {injected_url}: {exc}")
        finally:
            self.driver_pool.release(driver)

    def run(self, targets: list[str]) -> None:
        self.stats = ScanStats()
        tasks = [(url, payload) for url in targets for payload in self.payloads]
        self.logger.info(
            f"{Fore.CYAN}[i] Scanning {len(targets)} target(s) with {len(self.payloads)} "
            f"payload(s) -> {len(tasks)} total requests, {self.threads} thread(s){Style.RESET_ALL}\n"
        )

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self._check_injection, url, payload) for url, payload in tasks]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:  # noqa: BLE001 - keep scanning on worker errors
                        with self.findings_lock:
                            self.stats.total_errors += 1
                        self.logger.debug(f"[!] Worker error: {exc}")
        except KeyboardInterrupt:
            self.logger.warning(f"\n{Fore.RED}[!] Scan interrupted by user. Shutting down...{Style.RESET_ALL}")
            raise
        finally:
            self.stats.end_time = time.time()
            self.driver_pool.shutdown()


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def print_summary(scanner: XSSScanner, logger: logging.Logger) -> None:
    print()
    print(f"{Fore.YELLOW}{'-' * 50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Scan finished.{Style.RESET_ALL}")
    print(f"  Vulnerabilities found : {Fore.GREEN}{len(scanner.findings)}{Style.RESET_ALL}")
    print(f"  Requests sent         : {scanner.stats.total_requests}")
    print(f"  Errors                : {scanner.stats.total_errors}")
    print(f"  Time taken            : {scanner.stats.elapsed}s")
    print(f"{Fore.YELLOW}{'-' * 50}{Style.RESET_ALL}")


def write_report(scanner: XSSScanner, output_path: str, logger: logging.Logger) -> None:
    ext = os.path.splitext(output_path)[1].lower()

    try:
        if ext == ".json":
            _write_json_report(scanner, output_path)
        elif ext in (".html", ".htm"):
            _write_html_report(scanner, output_path)
        else:
            _write_text_report(scanner, output_path)
    except OSError as exc:
        logger.error(f"[!] Failed to write report to '{output_path}': {exc}")
        return

    logger.info(f"{Fore.CYAN}[i] Report saved to {output_path}{Style.RESET_ALL}")


def _write_json_report(scanner: XSSScanner, path: str) -> None:
    data = {
        "tool": "Reflectra-XSS",
        "version": VERSION,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "vulnerabilities_found": len(scanner.findings),
            "requests_sent": scanner.stats.total_requests,
            "errors": scanner.stats.total_errors,
            "time_taken_seconds": scanner.stats.elapsed,
        },
        "findings": [
            {
                "target_url": f.target_url,
                "payload": f.payload,
                "injected_url": f.injected_url,
                "dialog_text": f.dialog_text,
                "timestamp": f.timestamp,
            }
            for f in scanner.findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _write_text_report(scanner: XSSScanner, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("Reflectra-XSS Scan Report\n")
        fh.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")
        fh.write(f"Vulnerabilities found: {len(scanner.findings)}\n")
        fh.write(f"Requests sent: {scanner.stats.total_requests}\n")
        fh.write(f"Errors: {scanner.stats.total_errors}\n")
        fh.write(f"Time taken: {scanner.stats.elapsed}s\n")
        fh.write("-" * 60 + "\n")
        for f in scanner.findings:
            fh.write(f"[VULNERABLE] {f.injected_url}\n")
            fh.write(f"  Target   : {f.target_url}\n")
            fh.write(f"  Payload  : {f.payload}\n")
            fh.write(f"  Dialog   : {f.dialog_text}\n")
            fh.write(f"  Time     : {f.timestamp}\n\n")


def _write_html_report(scanner: XSSScanner, path: str) -> None:
    rows = "\n".join(
        f"""<tr>
            <td>{i + 1}</td>
            <td class="mono">{_escape(f.target_url)}</td>
            <td class="mono">{_escape(f.injected_url)}</td>
            <td class="mono">{_escape(f.payload)}</td>
            <td>{_escape(f.dialog_text)}</td>
            <td>{f.timestamp}</td>
        </tr>"""
        for i, f in enumerate(scanner.findings)
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Reflectra-XSS Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0d1117; color:#c9d1d9; margin:2rem; }}
  h1 {{ color:#58a6ff; }}
  .summary {{ background:#161b22; padding:1rem 1.5rem; border-radius:8px; margin-bottom:1.5rem; }}
  table {{ width:100%; border-collapse:collapse; background:#161b22; }}
  th, td {{ padding:0.6rem 0.8rem; border-bottom:1px solid #30363d; text-align:left; font-size:0.85rem; }}
  th {{ background:#21262d; color:#58a6ff; }}
  .mono {{ font-family: Consolas, monospace; word-break:break-all; }}
  footer {{ margin-top:2rem; color:#6e7681; font-size:0.8rem; }}
</style>
</head>
<body>
  <h1>Reflectra-XSS &mdash; Scan Report</h1>
  <div class="summary">
    <div>Generated: {datetime.now().isoformat(timespec='seconds')}</div>
    <div>Vulnerabilities found: <b>{len(scanner.findings)}</b></div>
    <div>Requests sent: {scanner.stats.total_requests}</div>
    <div>Errors: {scanner.stats.total_errors}</div>
    <div>Time taken: {scanner.stats.elapsed}s</div>
  </div>
  <table>
    <thead>
      <tr><th>#</th><th>Target</th><th>Injected URL</th><th>Payload</th><th>Dialog Text</th><th>Timestamp</th></tr>
    </thead>
    <tbody>
      {rows if rows else '<tr><td colspan="6">No vulnerabilities found.</td></tr>'}
    </tbody>
  </table>
  <footer>Generated By Pratik Khairnar-XSS v{VERSION} &mdash; By Pratik Khairnar</footer>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reflectra_xss.py",
        description="Reflectra-XSS - Cross-Site Scripting scanner (By Pratik Khairnar)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target_group = parser.add_argument_group("target selection")
    target_group.add_argument("-u", "--url", help="Single target URL to scan")
    target_group.add_argument("-f", "--file", help="Path to a file containing one target URL per line")

    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument(
        "-p",
        "--payload",
        default=DEFAULT_PAYLOAD_FILE,
        help="Path to a payload file, or a single literal payload string",
    )
    scan_group.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent worker threads")
    scan_group.add_argument(
        "--timeout", type=float, default=2.0, help="Seconds to wait for a JS dialog before marking not vulnerable"
    )

    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o", "--output", help="Write results to a report file (.json, .html, or .txt based on extension)"
    )
    output_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug output")
    output_group.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")
    output_group.add_argument("--version", action="version", version=f"Reflectra-XSS {VERSION}")

    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error("You must specify a target with --url or --file.")

    logger = setup_logging(args.verbose)

    if not args.no_banner:
        print(BANNER)

    targets = load_targets(args, logger)
    payloads = load_payloads(args.payload, logger)

    logger.info(f"{Fore.CYAN}[i] Loaded {len(targets)} target(s) and {len(payloads)} payload(s){Style.RESET_ALL}")

    scanner = XSSScanner(
        payloads=payloads,
        threads=args.threads,
        timeout=args.timeout,
        logger=logger,
        verbose=args.verbose,
    )

    try:
        scanner.run(targets)
    except KeyboardInterrupt:
        print_summary(scanner, logger)
        if args.output:
            write_report(scanner, args.output, logger)
        return 130
    except Exception as exc:  # noqa: BLE001
        logger.error(f"{Fore.RED}[!] Fatal error during scan: {exc}{Style.RESET_ALL}")
        return 1

    print_summary(scanner, logger)

    if args.output:
        write_report(scanner, args.output, logger)

    return 0 if not scanner.findings else 0


if __name__ == "__main__":
    sys.exit(main())
