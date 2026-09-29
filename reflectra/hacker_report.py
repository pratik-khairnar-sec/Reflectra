"""
reflectra.hacker_report
--------------------------
Standalone report renderer — dark/terminal "hacker" theme, findings grouped
by bug class (XSS context: HTML / Attribute / Script / URI / DOM-Sink /
Blind), for portfolio/writeup/screenshot use.

This module is 100% additive: it only reads `engine.findings` and
`plan_stats` (already produced by the untouched detection core in
browser.py/planner.py) and renders them differently. No detection,
probing, or planning logic lives here or is modified elsewhere.

Grouping key: Finding.context (from browser.py) already carries the
reflection context string (e.g. "html", "attr-dq/script", "fallback:TIMEOUT",
"blind"). We bucket those into a small set of human bug classes so the
report reads like a real triage doc, not raw internals.
"""

from __future__ import annotations

import html as htmlmod
from collections import defaultdict
from datetime import datetime

from .browser import VERSION
from .models import FindingKind


def _bug_class(context: str, kind: FindingKind) -> str:
    ctx = (context or "").lower()
    if kind == FindingKind.BLIND_INJECTION:
        return "Blind / Stored XSS"
    if kind == FindingKind.ERROR:
        return "Scan Errors"
    if "fallback" in ctx or "ambiguous" in ctx:
        return "Full-Coverage Fallback (probe uncertain)"
    if "script" in ctx:
        return "Script-Context XSS"
    if "attr" in ctx:
        return "Attribute-Context XSS"
    if "uri" in ctx:
        return "URI-Context XSS"
    if "comment" in ctx:
        return "HTML-Comment XSS"
    if "unreflected" in ctx or "dom" in ctx:
        return "DOM / Client-Side XSS"
    if "html" in ctx:
        return "HTML-Context XSS"
    return "Other"


_KIND_BADGE = {
    FindingKind.CONFIRMED_XSS: ("CONFIRMED", "#39ff14"),
    FindingKind.SINK_REACHABLE_LEAD: ("SINK LEAD", "#ffb000"),
    FindingKind.BLIND_INJECTION: ("BLIND SENT", "#00d9ff"),
    FindingKind.ERROR: ("ERROR", "#ff2d55"),
    FindingKind.INCONCLUSIVE: ("INCONCLUSIVE", "#7d7d7d"),
}

_SEVERITY_ORDER = [
    "Script-Context XSS",
    "HTML-Context XSS",
    "Attribute-Context XSS",
    "URI-Context XSS",
    "DOM / Client-Side XSS",
    "Blind / Stored XSS",
    "HTML-Comment XSS",
    "Full-Coverage Fallback (probe uncertain)",
    "Scan Errors",
    "Other",
]


def _esc(s: str) -> str:
    return htmlmod.escape(s or "")


def render_hacker_report(engine, plan_stats, target_label: str = "") -> str:
    """Return a full self-contained dark/hacker-themed HTML report string.
    Does not touch disk -- caller decides where to write it."""
    groups: dict[str, list] = defaultdict(list)
    for f in engine.findings:
        groups[_bug_class(f.context, f.kind)].append(f)

    ordered_classes = [c for c in _SEVERITY_ORDER if c in groups] + \
                       [c for c in groups if c not in _SEVERITY_ORDER]

    confirmed = sum(1 for f in engine.findings if f.kind == FindingKind.CONFIRMED_XSS)
    leads = sum(1 for f in engine.findings if f.kind == FindingKind.SINK_REACHABLE_LEAD)
    blind = sum(1 for f in engine.findings if f.kind == FindingKind.BLIND_INJECTION)
    errors = sum(1 for f in engine.findings if f.kind == FindingKind.ERROR)

    sections = []
    poc_index = 0
    for cls in ordered_classes:
        rows = groups[cls]
        row_html = []
        for f in rows:
            badge_text, badge_color = _KIND_BADGE.get(f.kind, ("?", "#888"))
            detail = f.dialog_text or f.detail
            is_poc = f.kind == FindingKind.CONFIRMED_XSS
            poc_id = f"poc-{poc_index}"
            poc_index += 1
            copy_btn = f'<button class="copy-btn" onclick="copyPayload(\'{poc_id}\')">copy payload</button>' if is_poc else ""
            row_html.append(f"""
            <div class="finding{' poc' if is_poc else ''}">
              <span class="badge" style="color:{badge_color};border-color:{badge_color}">[{badge_text}]</span>
              <a class="url" href="{_esc(f.injected_url)}" target="_blank" rel="noopener noreferrer">{_esc(f.injected_url)}</a>
              <div class="meta">payload:
                <code id="{poc_id}">{_esc(f.payload)}</code>
                {copy_btn}
              </div>
              {f'<div class="meta">-&gt; {_esc(detail)}</div>' if detail else ''}
              <div class="ts">{_esc(f.timestamp)}</div>
            </div>""")
        sections.append(f"""
        <section class="bugclass">
          <h2>&gt; {_esc(cls)} <span class="count">[{len(rows)}]</span></h2>
          {''.join(row_html)}
        </section>""")

    # Tabular view (all findings, one row each) for people who prefer a table
    # over grouped cards -- same data, different layout, toggled client-side.
    table_rows = "\n".join(
        f"""<tr>
          <td>{i+1}</td>
          <td class="badgecell" style="color:{_KIND_BADGE.get(f.kind, ('?', '#888'))[1]}">{_KIND_BADGE.get(f.kind, ('?', '#888'))[0]}</td>
          <td>{_esc(_bug_class(f.context, f.kind))}</td>
          <td><a href="{_esc(f.injected_url)}" target="_blank" rel="noopener noreferrer">{_esc(f.injected_url[:90])}{'...' if len(f.injected_url) > 90 else ''}</a></td>
          <td class="mono">{_esc(f.payload[:60])}{'...' if len(f.payload) > 60 else ''}</td>
          <td>{_esc(f.dialog_text or f.detail)}</td>
        </tr>"""
        for i, f in enumerate(engine.findings)
    )

    plan_html = ""
    if plan_stats is not None:
        plan_html = f"""
        <div class="plan">
          <div>points probed: {plan_stats.total_points}</div>
          <div>reflected(context ok): {plan_stats.reflected_points}</div>
          <div>ambiguous: {plan_stats.ambiguous_points}</div>
          <div>not reflected: {plan_stats.not_reflected_points}</div>
          <div>probe failed (fallback): {plan_stats.fallback_points}</div>
          <div>browser tasks: {plan_stats.total_tasks}</div>
        </div>"""

    body = ''.join(sections) if sections else '<div class="finding">No findings recorded.</div>'
    table_body = table_rows if engine.findings else '<tr><td colspan="6">No findings.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Reflectra // {_esc(target_label) or 'Scan Report'}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
  :root {{
    --bg:#050807; --panel:#0a120d; --line:#123821; --green:#39ff14;
    --dim:#5fae6d; --amber:#ffb000; --cyan:#00d9ff; --red:#ff2d55;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    background:var(--bg); color:var(--green); font-family:'Share Tech Mono', monospace;
    margin:0; padding:2rem; background-image:
      repeating-linear-gradient(0deg, rgba(57,255,20,0.03) 0px, rgba(57,255,20,0.03) 1px, transparent 1px, transparent 3px);
  }}
  .crt {{ max-width:1100px; margin:0 auto; }}
  h1 {{ font-size:1.6rem; letter-spacing:2px; text-shadow:0 0 8px var(--green); margin-bottom:0.2rem; }}
  .sub {{ color:var(--dim); margin-bottom:1.2rem; }}
  .prompt {{ color:var(--dim); }}
  .summary {{
    border:1px solid var(--line); background:var(--panel); padding:1rem 1.4rem;
    margin-bottom:1.6rem; box-shadow:0 0 20px rgba(57,255,20,0.08);
  }}
  .stat {{ display:inline-block; margin:0.25rem 1.4rem 0.25rem 0; }}
  .stat b {{ font-size:1.3rem; display:block; }}
  .stat.confirmed b {{ color:var(--green); text-shadow:0 0 6px var(--green); }}
  .stat.leads b {{ color:var(--amber); }}
  .stat.blind b {{ color:var(--cyan); }}
  .stat.errors b {{ color:var(--red); }}
  .plan {{ margin-top:0.8rem; color:var(--dim); font-size:0.82rem; display:flex; flex-wrap:wrap; gap:1rem; }}
  .viewtoggle {{ margin-bottom:1.2rem; }}
  .viewtoggle button {{
    background:var(--panel); color:var(--green); border:1px solid var(--line); padding:0.4rem 0.9rem;
    font-family:inherit; cursor:pointer; margin-right:0.5rem; border-radius:2px;
  }}
  .viewtoggle button.active {{ background:var(--green); color:#001a00; font-weight:bold; }}
  .bugclass {{ border-left:2px solid var(--line); padding-left:1rem; margin-bottom:1.6rem; }}
  .bugclass h2 {{ font-size:1.05rem; color:var(--green); margin:0 0 0.6rem 0; }}
  .count {{ color:var(--dim); font-size:0.85rem; }}
  .finding {{
    background:var(--panel); border:1px solid var(--line); border-radius:2px;
    padding:0.6rem 0.9rem; margin-bottom:0.5rem; font-size:0.85rem;
  }}
  .finding.poc {{ border-left:3px solid var(--green); }}
  .badge {{
    display:inline-block; border:1px solid; padding:0.05rem 0.5rem; border-radius:3px;
    font-size:0.72rem; margin-right:0.5rem; letter-spacing:1px;
  }}
  .url {{ word-break:break-all; color:var(--cyan); text-decoration:none; }}
  .url:hover {{ text-decoration:underline; }}
  .meta {{ color:var(--dim); margin-top:0.25rem; word-break:break-all; }}
  .meta code {{ color:#c9f7c9; background:#08150c; padding:0.1rem 0.4rem; border-radius:2px; }}
  .copy-btn {{
    background:none; border:1px solid var(--line); color:var(--dim); font-size:0.68rem;
    padding:0.1rem 0.5rem; margin-left:0.5rem; cursor:pointer; border-radius:2px; font-family:inherit;
  }}
  .copy-btn:hover {{ color:var(--green); border-color:var(--green); }}
  .copy-btn.copied {{ color:var(--green); border-color:var(--green); }}
  .ts {{ color:#3a5c42; font-size:0.7rem; margin-top:0.3rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.78rem; }}
  th, td {{ padding:0.4rem 0.6rem; border-bottom:1px solid var(--line); text-align:left; word-break:break-all; }}
  th {{ color:var(--green); border-bottom:1px solid var(--green); }}
  td a {{ color:var(--cyan); text-decoration:none; }}
  td.mono {{ font-family:'Share Tech Mono', monospace; color:#c9f7c9; }}
  #cardsView, #tableView {{ display:block; }}
  #tableView {{ display:none; }}
  footer {{ color:var(--dim); margin-top:2rem; font-size:0.75rem; border-top:1px dashed var(--line); padding-top:0.8rem; }}
  footer a {{ color:var(--green); }}
</style></head>
<body>
  <div class="crt">
    <div class="prompt">root@reflectra:~$ ./reflectra.py --report --style hacker</div>
    <h1>REFLECTRA // SCAN REPORT</h1>
    <div class="sub">{_esc(target_label) or 'target(s) as configured'} &nbsp;|&nbsp; generated {datetime.now().isoformat(timespec='seconds')}</div>

    <div class="summary">
      <div class="stat confirmed"><b>{confirmed}</b>CONFIRMED XSS</div>
      <div class="stat leads"><b>{leads}</b>SINK LEADS</div>
      <div class="stat blind"><b>{blind}</b>BLIND SENT</div>
      <div class="stat errors"><b>{errors}</b>ERRORS</div>
      <div class="stat"><b>{engine.stats.total_requests}</b>BROWSER REQUESTS</div>
      <div class="stat"><b>{engine.stats.elapsed}s</b>TIME</div>
      {plan_html}
    </div>

    <div class="viewtoggle">
      <button id="btnCards" class="active" onclick="showView('cards')">&#9776; Grouped by bug class</button>
      <button id="btnTable" onclick="showView('table')">&#9638; Table view</button>
    </div>

    <div id="cardsView">
      {body}
    </div>
    <div id="tableView">
      <table>
        <thead><tr><th>#</th><th>Kind</th><th>Bug Class</th><th>URL (click to verify manually)</th><th>Payload</th><th>Dialog / Detail</th></tr></thead>
        <tbody>{table_body}</tbody>
      </table>
    </div>

    <footer>
      Generated by <b>Reflectra v{VERSION}</b> &mdash; Context-Aware XSS Scanner<br>
      Author: Pratik Khairnar &nbsp;|&nbsp; <a href="https://github.com/pratik-khairnar-sec" target="_blank" rel="noopener noreferrer">github.com/pratik-khairnar-sec</a><br>
      Sink-reachable and blind-injection entries are UNCONFIRMED leads, not proven vulnerabilities.
      Error entries mean a payload could not be tested -- not "not vulnerable". Click any URL to open it in a
      new tab for manual proof-of-concept verification.
    </footer>
  </div>

  <script>
    function showView(view) {{
      document.getElementById('cardsView').style.display = view === 'cards' ? 'block' : 'none';
      document.getElementById('tableView').style.display = view === 'table' ? 'block' : 'none';
      document.getElementById('btnCards').classList.toggle('active', view === 'cards');
      document.getElementById('btnTable').classList.toggle('active', view === 'table');
    }}
    function copyPayload(id) {{
      const el = document.getElementById(id);
      const text = el.textContent;
      const btn = event.target;
      const done = () => {{ btn.textContent = 'copied!'; btn.classList.add('copied');
                             setTimeout(() => {{ btn.textContent = 'copy payload'; btn.classList.remove('copied'); }}, 1500); }};
      if (navigator.clipboard && window.isSecureContext) {{
        navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
      }} else {{
        fallbackCopy(text, done);
      }}
    }}
    function fallbackCopy(text, cb) {{
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try {{ document.execCommand('copy'); cb(); }} catch (e) {{}}
      document.body.removeChild(ta);
    }}
  </script>
</body></html>"""


def write_hacker_report(engine, plan_stats, output_path: str, target_label: str = "") -> None:
    content = render_hacker_report(engine, plan_stats, target_label)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
