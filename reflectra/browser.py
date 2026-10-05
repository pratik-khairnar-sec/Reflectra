"""
reflectra.browser
--------------------
THIS MODULE IS THE ORIGINAL VAELION-XSS DETECTION CORE.

DriverPool and the per-payload confirmation routine below are carried over
from legacy_vaelion_xss.py's DriverPool and XSSScanner._check_injection
almost line-for-line. This is intentional: that code was tested and
working, and the whole point of Reflectra's optimization layer is to feed
this engine a smaller, better-prioritized task list -- not to replace it.

Diff vs. the original (every change is additive or a bugfix, none change
detection semantics):
  1. Original used one implicit exception path per payload. Here, failure
     is classified into explicit outcomes (ERROR vs INCONCLUSIVE) so a
     WebDriverException/timeout is never recorded as "not vulnerable" --
     it produces a Finding with kind=ERROR, distinguishable in reports
     from a payload that was actually tried and did not fire a dialog.
  2. Cookie seeding was added for --cookie/--header auth support (opt-in,
     no-op when no cookies are supplied).
  3. Optional post-negative DOM-sink probe (reflectra.sinks) was added
     AFTER the original alert-wait/timeout logic, not instead of it -- it
     only runs once the original confirmation path has already concluded
     "no dialog fired".
  4. Driver creation/pooling, Chrome options, alert/confirm/prompt
     handling via EC.alert_is_present(), and the UnexpectedAlertPresentException
     recovery path are unchanged from the original.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Optional
from urllib.parse import urlsplit

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

from .models import Finding, FindingKind
from .sinks import find_reachable_sinks
from .urltools import ParamPoint

VERSION = "7.0.0"


# --------------------------------------------------------------------------- #
# Driver pool -- unchanged from legacy_vaelion_xss.DriverPool, plus optional
# cookie seeding for authenticated scans.
# --------------------------------------------------------------------------- #

class DriverPool:
    """Thread-safe pool of headless Chrome WebDriver instances, created lazily
    and reused across worker threads to avoid the cost of spinning up a new
    browser per request. (Original v1 docstring, unchanged behavior.)"""

    def __init__(self, logger: logging.Logger, cookies: Optional[dict] = None, insecure: bool = False):
        self._pool: Queue = Queue()
        self._all_drivers: list = []
        self._lock = threading.Lock()
        self._logger = logger
        self._cookies = cookies or {}
        self._insecure = insecure

    def _create_driver(self):
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-infobars")
        options.add_argument("--disable-notifications")
        options.add_argument("--disable-gpu")
        if self._insecure:
            options.add_argument("--ignore-certificate-errors")
        options.page_load_strategy = "eager"

        logging.getLogger("WDM").setLevel(logging.ERROR)
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(30)
        with self._lock:
            self._all_drivers.append(driver)
        return driver

    def _seed_cookies(self, driver, url: str) -> None:
        if not self._cookies:
            return
        try:
            scheme, netloc, *_ = urlsplit(url)
            driver.get(f"{scheme}://{netloc}/")
            for name, value in self._cookies.items():
                try:
                    driver.add_cookie({"name": name, "value": value})
                except WebDriverException:
                    pass
        except WebDriverException:
            pass

    def acquire(self, seed_url: Optional[str] = None):
        try:
            driver = self._pool.get_nowait()
        except Empty:
            driver = self._create_driver()
            if seed_url:
                self._seed_cookies(driver, seed_url)
        return driver

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


@dataclass
class ScanStats:
    total_requests: int = 0
    total_errors: int = 0
    skipped_no_reflection: int = 0
    payloads_saved_by_context: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0

    @property
    def elapsed(self) -> float:
        end = self.end_time or time.time()
        return round(end - self.start_time, 2)


@dataclass
class Task:
    point: ParamPoint
    payload: str
    context: str = "unknown"


class BrowserConfirmationEngine:
    """The original detection core. `confirm_one()` is
    legacy_vaelion_xss.XSSScanner._check_injection, restructured to operate
    on one (point, payload) Task instead of expanding a single target URL
    into every parameter variant itself -- that expansion now happens once,
    up front, in urltools.injection_points(), shared with the probe phase so
    both phases inject into exactly the same points. The alert-wait,
    UnexpectedAlertPresentException recovery, and WebDriverException
    handling are otherwise the same control flow as v1."""

    def __init__(
        self,
        threads: int,
        dialog_timeout: float,
        logger: logging.Logger,
        cookies: Optional[dict] = None,
        insecure: bool = False,
        probe_sinks: bool = True,
        verbose: bool = False,
        stop_on_first_confirmed: bool = False,
        max_confirmed: Optional[int] = None,
        on_finding: Optional[callable] = None,
    ):
        self.threads = max(1, threads)
        self.dialog_timeout = dialog_timeout
        self.logger = logger
        self.driver_pool = DriverPool(logger, cookies=cookies, insecure=insecure)
        self.probe_sinks = probe_sinks
        self.verbose = verbose
        self.findings: list[Finding] = []
        self._lock = threading.Lock()
        self.stats = ScanStats()
        # Additive, opt-in, default-off: none of these change detection
        # semantics for any caller that doesn't explicitly set them.
        # `max_confirmed` is the general form (stop once N confirmed XSS have
        # been found); `stop_on_first_confirmed=True` is a convenience alias
        # for max_confirmed=1 when max_confirmed isn't explicitly given.
        if max_confirmed is None and stop_on_first_confirmed:
            max_confirmed = 1
        self.max_confirmed = max_confirmed
        self.stop_on_first_confirmed = stop_on_first_confirmed or (max_confirmed is not None)
        self._confirmed_count = 0
        self._stop_event = threading.Event()
        self.on_finding = on_finding  # optional callback(Finding) for live terminal/UI feedback

    def confirm_one(self, task: Task) -> None:
        """Original per-payload confirmation logic (v1 _check_injection),
        operating on a single pre-built injected URL."""
        if self.stop_on_first_confirmed and self._stop_event.is_set():
            # The confirmed-count threshold was already reached -- skip remaining
            # queued tasks without touching the browser. Opt-in only.
            return

        injected_url = task.point.render(task.payload)

        try:
            driver = self.driver_pool.acquire(seed_url=injected_url)
        except Exception as exc:  # noqa: BLE001 - driver/webdriver-manager failure, e.g. no
            # Chrome binary, no network to fetch chromedriver, permission errors, etc.
            # This is NOT "payload tried, not vulnerable" -- it's "payload never tested".
            # Must be visible in reports, not silently swallowed into total_errors with
            # no corresponding Finding (that was the exact bug this comment replaces).
            with self._lock:
                self.stats.total_errors += 1
            self.logger.error(f"[!] Could not acquire browser driver for {injected_url}: {exc}")
            self._record(FindingKind.ERROR, task, injected_url, detail=f"driver acquisition failed: {exc}")
            return

        try:
            try:
                driver.get(injected_url)
                with self._lock:
                    self.stats.total_requests += 1

                try:
                    alert = WebDriverWait(driver, self.dialog_timeout).until(EC.alert_is_present())
                    dialog_text = alert.text
                    alert.accept()
                    self._record(FindingKind.CONFIRMED_XSS, task, injected_url, dialog_text=dialog_text)
                    return
                except TimeoutException:
                    pass  # No dialog within timeout -- original behavior: fall through, not an error.

            except UnexpectedAlertPresentException:
                # A dialog fired during navigation itself; original v1 treats this as a hit too.
                try:
                    alert = driver.switch_to.alert
                    dialog_text = alert.text
                    alert.accept()
                    self._record(FindingKind.CONFIRMED_XSS, task, injected_url, dialog_text=dialog_text)
                    return
                except WebDriverException:
                    pass
            except WebDriverException as exc:
                # v1 counted this as total_errors and moved on. v2 additionally
                # records an explicit ERROR finding so it is visible in reports
                # and never conflated with "payload tried, not vulnerable".
                with self._lock:
                    self.stats.total_errors += 1
                self.logger.debug(f"[!] WebDriver error on {injected_url}: {exc}")
                self._record(FindingKind.ERROR, task, injected_url, detail=str(exc))
                return

            # No dialog fired -- original v1 behavior stops here (logs "not vulnerable" in
            # verbose mode). v2 additionally runs a static sink check as an UNCONFIRMED lead.
            if self.probe_sinks:
                self._probe_sinks(driver, task, injected_url)
            elif self.verbose:
                self.logger.debug(f"[-] Not vulnerable {injected_url}")

        finally:
            self.driver_pool.release(driver)

    def _probe_sinks(self, driver, task: Task, injected_url: str) -> None:
        try:
            source = driver.execute_script("return document.documentElement.outerHTML;")
        except WebDriverException:
            return
        for hit in find_reachable_sinks(source, task.payload):
            self._record(
                FindingKind.SINK_REACHABLE_LEAD, task, injected_url,
                detail=f"{hit.sink} :: {hit.snippet}",
            )

    def _record(self, kind: FindingKind, task: Task, injected_url: str, dialog_text: str = "", detail: str = "") -> None:
        finding = Finding(
            kind=kind,
            target_url=task.point.base_url,
            payload=task.payload,
            injected_url=injected_url,
            context=task.context,
            dialog_text=dialog_text,
            detail=detail,
        )
        with self._lock:
            self.findings.append(finding)

        if self.on_finding is not None:
            try:
                self.on_finding(finding)
            except Exception:  # noqa: BLE001 - a UI callback must never break the scan
                pass

        if kind == FindingKind.CONFIRMED_XSS:
            with self._lock:
                self._confirmed_count += 1
                count = self._confirmed_count
            self.logger.info(f"[+] CONFIRMED [{task.context}] {injected_url} (dialog: {dialog_text!r})")
            if self.max_confirmed is not None and count >= self.max_confirmed:
                self.logger.info(f"[i] Reached {count}/{self.max_confirmed} confirmed XSS -- stopping scan.")
                self._stop_event.set()
        elif kind == FindingKind.SINK_REACHABLE_LEAD:
            self.logger.info(f"[~] SINK-REACHABLE-LEAD [{task.context}] {injected_url} :: {detail}")
        elif kind == FindingKind.ERROR:
            self.logger.debug(f"[!] ERROR {injected_url} :: {detail}")

    def run(self, tasks: list[Task]) -> None:
        """Same ThreadPoolExecutor pattern as v1 XSSScanner.run(): one
        submitted future per task, driver pool shared and reused, one
        worker's WebDriverException does not cancel or block the others."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        self.stats.start_time = time.time()
        self.logger.info(f"[i] Browser confirmation: {len(tasks)} candidate(s), {self.threads} thread(s)")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self.confirm_one, t) for t in tasks]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:  # noqa: BLE001 - one worker's crash must not kill the scan
                        with self._lock:
                            self.stats.total_errors += 1
                        self.logger.debug(f"[!] Worker error: {exc}")
                    if self.stop_on_first_confirmed and self._stop_event.is_set():
                        cancelled = sum(1 for f in futures if f.cancel())
                        if cancelled:
                            self.logger.info(f"[i] Stop-on-first-confirmed: cancelled {cancelled} pending task(s).")
                        break
        finally:
            self.stats.end_time = time.time()
            self.driver_pool.shutdown()

    def run_blind_injection(self, points: list[ParamPoint], blind_payloads: list[str], logger: logging.Logger) -> int:
        import requests

        sent = 0
        session = requests.Session()
        for point in points:
            for payload in blind_payloads:
                url = point.render(payload)
                try:
                    session.get(url, timeout=8)
                    self._record(FindingKind.BLIND_INJECTION, Task(point, payload, "blind"), url)
                    sent += 1
                except requests.RequestException as exc:
                    logger.debug(f"[blind] request failed for {url}: {exc}")
        logger.info(
            f"[i] Blind XSS: injected {sent} payload/point combination(s). "
            f"This confirms INJECTION only -- check your external collector for CONFIRMATION."
        )
        return sent
