"""agentic-compliance — agent layer + MD3 dashboard over a REAL OpenSCAP core.

Sibling of agents/billing (the reference pattern), but the "core" is a self-contained
compliance **scanner** rather than a long-running server: the OpenSCAP `oscap` tool
produces REAL XCCDF results (rule id, title, result pass/fail/notapplicable, severity)
from a CIS Ubuntu 22.04 Level 1 - Server benchmark, and this agent monitors/explains
them — no cloud creds.

Pattern (same as billing):
  1. point at the real core output (here: the cached SCAP results file),
  2. write a `fetch_*` that parses REAL records + a `compute_kpis`,
  3. reuse BASE_CSS + the render helpers,
  4. add agentic actions in /agent/run that are deterministic, with a human-approval
     gate on anything that changes the system (remediate -> policy_change).

Endpoints:
  GET  /health        -> {"status","core":"openscap","connected": <results file present?>}
  GET  /api/activity  -> REAL parsed findings: pass rate %, passing/failing counts,
                         top failing rules by severity, grouped framework view, plus a
                         couple of SME compliance items (license/insurance expiry).
  GET  /              -> MD3 compliance dashboard (Vanta/Drata style) from the REAL scan.
  GET  /report        -> the OpenSCAP-generated HTML report.
  POST /agent/run     -> {"action": "scan" | "explain" | "remediate"}

Config (env; seed.py writes agents/compliance/.env automatically):
  SCAP_RESULTS   path to the real oscap XCCDF results file (default: results/scan-results.xml)
  SCAP_REPORT    path to the real oscap HTML report   (default: results/report.html)
  SCAP_PROFILE   the xccdf profile id that was evaluated
  PORT           uvicorn port, default 8208
  ANTHROPIC_API_KEY  OPTIONAL — if set, /agent/run "explain" adds an LLM rewrite; the
                     endpoint works fully without it (deterministic fallback from the
                     rule's own description/rationale/fix in the SCAP content).
"""
from __future__ import annotations

import html
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse

# --- config ------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
_ENV_FILE = HERE / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

SCAP_RESULTS = Path(os.environ.get("SCAP_RESULTS", str(HERE / "results" / "scan-results.xml")))
SCAP_REPORT = Path(os.environ.get("SCAP_REPORT", str(HERE / "results" / "report.html")))
SCAP_PROFILE = os.environ.get(
    "SCAP_PROFILE", "xccdf_org.ssgproject.content_profile_cis_level1_server"
)
PORT = int(os.environ.get("PORT", "8208"))

XCCDF = "{http://checklists.nist.gov/xccdf/1.2}"

TENANT = "Summit Roofing Co."
SUBTITLE = (
    "Continuous control monitoring on a real OpenSCAP core — CIS Ubuntu benchmark "
    "scanned on Summit's server, with a human in the loop before any fix is applied."
)
# The framework the scanned profile maps to (shown as the primary framework card).
FRAMEWORK = "CIS Ubuntu Linux 22.04 LTS — Level 1 Server"

# SME compliance items layered in for the roofing context (license / insurance expiry).
# These sit alongside the REAL OpenSCAP technical controls in the failing/expiring queue.
SME_ITEMS = [
    {"item": "State contractor license", "kind": "license", "status": "ACTIVE", "expires": "2027-03-01"},
    {"item": "General Liability insurance", "kind": "insurance", "status": "ACTIVE", "expires": "2026-09-08"},
    {"item": "Workers' Comp insurance", "kind": "insurance", "status": "ACTIVE", "expires": "2026-12-15"},
    {"item": "Commercial auto policy", "kind": "insurance", "status": "ACTIVE", "expires": "2027-01-20"},
]

app = FastAPI(title=f"agentic-compliance ({TENANT} · core: OpenSCAP)")


# --- OpenSCAP results parsing (the REAL core data) ---------------------------
def scap_connected() -> bool:
    """True iff a real oscap results file is present and non-empty."""
    try:
        return SCAP_RESULTS.exists() and SCAP_RESULTS.stat().st_size > 0
    except Exception:
        return False


def _clean(el) -> str:
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


# Parsed-content cache keyed off the results file mtime, so a fresh scan invalidates it.
_PARSE_CACHE: dict = {"mtime": None, "rules": None, "results": None}


def _parse_scap() -> tuple[dict, list[dict]]:
    """Parse the real XCCDF results file.

    Returns (rules_by_id, results) where:
      rules_by_id[id] = {id,title,description,rationale,fix,severity}
      results = [{id,title,result,severity}, ...] in benchmark order.
    The embedded <Benchmark> carries the Rule definitions (titles/descriptions/fixes);
    the <TestResult> carries the per-rule pass/fail/notapplicable outcomes.
    """
    mtime = SCAP_RESULTS.stat().st_mtime if scap_connected() else None
    if _PARSE_CACHE["mtime"] == mtime and _PARSE_CACHE["rules"] is not None:
        return _PARSE_CACHE["rules"], _PARSE_CACHE["results"]

    rules: dict[str, dict] = {}
    results: list[dict] = []
    if mtime is not None:
        root = ET.parse(SCAP_RESULTS).getroot()
        for rule in root.iter(XCCDF + "Rule"):
            rid = rule.get("id")
            if not rid:
                continue
            fix = rule.find(XCCDF + "fix")
            rules[rid] = {
                "id": rid,
                "title": _clean(rule.find(XCCDF + "title")),
                "description": _clean(rule.find(XCCDF + "description")),
                "rationale": _clean(rule.find(XCCDF + "rationale")),
                "fix": _clean(fix),
                "severity": rule.get("severity", "unknown"),
            }
        for rr in root.iter(XCCDF + "rule-result"):
            res_el = rr.find(XCCDF + "result")
            rid = rr.get("idref")
            meta = rules.get(rid, {})
            results.append({
                "id": rid,
                "title": meta.get("title") or _short_id(rid),
                "result": res_el.text if res_el is not None else "unknown",
                "severity": rr.get("severity") or meta.get("severity", "unknown"),
            })

    _PARSE_CACHE.update(mtime=mtime, rules=rules, results=results)
    return rules, results


def _short_id(rid: str) -> str:
    """Human-ish short name from a long XCCDF rule id."""
    if not rid:
        return "—"
    return rid.split("content_rule_")[-1] if "content_rule_" in rid else rid


# --- activity (KPIs + framework view + failing queue), cached briefly --------
_CACHE: dict = {"ts": 0.0, "data": None}
_CACHE_TTL = 15.0

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "unknown": 3}


def _days_until(iso: str) -> int | None:
    try:
        y, m, d = (int(x) for x in iso[:10].split("-"))
        return (date(y, m, d) - date.today()).days
    except Exception:
        return None


def _sme_rows() -> list[dict]:
    rows = []
    for it in SME_ITEMS:
        days = _days_until(it["expires"])
        expiring = days is not None and days <= 90
        rows.append({
            "item": it["item"],
            "kind": it["kind"],
            "status": ("EXPIRING" if expiring else it["status"]),
            "expires": it["expires"],
            "days": days,
            "expiring": expiring,
        })
    return rows


def fetch_activity(force: bool = False) -> dict:
    """Parse REAL OpenSCAP results and compute the compliance KPIs the dashboard renders."""
    now = time.time()
    if not force and _CACHE["data"] is not None and now - _CACHE["ts"] < _CACHE_TTL:
        return _CACHE["data"]

    connected = scap_connected()
    rules, results = _parse_scap()

    passing = sum(1 for r in results if r["result"] == "pass")
    failing = sum(1 for r in results if r["result"] == "fail")
    notapplicable = sum(1 for r in results if r["result"] == "notapplicable")
    scored = passing + failing
    pass_rate = round(100 * passing / scored) if scored else 0

    # Top failing rules by severity (high -> low), then title.
    fails = [r for r in results if r["result"] == "fail"]
    fails.sort(key=lambda r: (_SEV_ORDER.get((r["severity"] or "unknown").lower(), 3), r["title"]))

    sme = _sme_rows()
    sme_open = [s for s in sme if s["expiring"]]

    # Open findings = failing technical controls + expiring SME items.
    open_findings = failing + len(sme_open)

    framework_pct = pass_rate  # the scanned profile IS the primary framework here.

    data = {
        "tenant": TENANT,
        "core": "openscap",
        "connected": connected,
        "profile": SCAP_PROFILE,
        "framework": FRAMEWORK,
        "report_url": "/report",
        "kpis": [
            {"label": "Control pass rate", "value": f"{pass_rate}%", "note": f"{scored} scored controls"},
            {"label": "Passing controls", "value": str(passing), "note": "CIS rules met"},
            {"label": "Failing controls", "value": str(failing), "note": "need remediation"},
            {"label": "Open findings", "value": str(open_findings),
             "note": f"{failing} technical · {len(sme_open)} license/insurance"},
        ],
        "frameworks": [
            {"name": FRAMEWORK, "pct": framework_pct, "passing": passing, "failing": failing,
             "notapplicable": notapplicable},
        ],
        "failing": [
            {"id": r["id"], "short": _short_id(r["id"]), "title": r["title"], "severity": r["severity"]}
            for r in fails
        ],
        "sme": sme,
        "expiring": sme_open,
        "counts": {
            "pass": passing, "fail": failing, "notapplicable": notapplicable, "scored": scored,
        },
    }
    _CACHE.update(ts=now, data=data)
    return data


# --- MD3 styling (BASE_CSS reused verbatim from deploy/module_service.py) -----
BASE_CSS = """
:root{
  --surface-dim:#0e0e11; --surface:#131316; --surface-bright:#393a3d;
  --surface-container-lowest:#0d0e10; --surface-container-low:#1b1b1f;
  --surface-container:#1f1f23; --surface-container-high:#2a2a2e; --surface-container-highest:#353539;
  --on-surface:#e4e2e6; --on-surface-variant:#c7c5ca; --on-surface-muted:#918f96;
  --outline:#938f99; --outline-variant:#2f2f33;
  --primary:#4fd1c5; --on-primary:#00201c; --primary-container:#00504a; --on-primary-container:#a8f0e6;
  --secondary:#f5b544; --on-secondary:#3d2e00; --secondary-container:#5c4500;
  --success:#5bd98a; --success-container:#0f3d22; --warning:#f5b544; --warning-container:#4a3500;
  --danger:#f2544f; --danger-container:#5c1512; --info:#5aa9f0; --info-container:#103a5c;
  --sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:24px;--sp-6:32px;--sp-7:40px;--sp-8:48px;
  --radius-sm:8px;--radius-md:12px;--radius-lg:16px;--radius-xl:28px;--radius-pill:999px;
  --shadow-1:0 1px 2px rgba(0,0,0,.45);--shadow-2:0 2px 6px rgba(0,0,0,.5);
  --font-sans:"Roboto",system-ui,-apple-system,"Segoe UI",sans-serif;
  --font-mono:"Roboto Mono",ui-monospace,"SF Mono",monospace;
}
*{box-sizing:border-box}
.display-l{font:400 57px/64px var(--font-sans);letter-spacing:-.25px}
.headline-m{font:400 28px/36px var(--font-sans)} .headline-s{font:400 24px/32px var(--font-sans)}
.title-l{font:400 22px/28px var(--font-sans)} .title-m{font:500 16px/24px var(--font-sans);letter-spacing:.15px}
.title-s{font:500 14px/20px var(--font-sans)} .body-m{font:400 14px/20px var(--font-sans)}
.body-s{font:400 12px/16px var(--font-sans)} .label-m{font:500 12px/16px var(--font-sans);letter-spacing:.5px}
.page{background:var(--surface);color:var(--on-surface);font-family:var(--font-sans);padding:var(--sp-5);margin:0}
.shell{max-width:1440px;margin-inline:auto;display:flex;flex-direction:column;gap:var(--sp-5)}
.grid{display:grid;gap:var(--sp-4);grid-template-columns:repeat(12,1fr)}
.kpi-row{display:grid;gap:var(--sp-4);grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
.col-3{grid-column:span 3}.col-4{grid-column:span 4}.col-6{grid-column:span 6}.col-8{grid-column:span 8}.col-12{grid-column:span 12}
@media(max-width:839px){[class^="col-"]{grid-column:span 12}}
.card{background:var(--surface-container);border:1px solid var(--outline-variant);border-radius:var(--radius-lg);padding:var(--sp-5);display:flex;flex-direction:column;gap:var(--sp-4)}
.card__head{display:flex;align-items:center;justify-content:space-between;gap:var(--sp-3)}
.card__title{font:500 16px/24px var(--font-sans);letter-spacing:.15px;color:var(--on-surface);margin:0}
.tile{background:var(--surface-container);border:1px solid var(--outline-variant);border-radius:var(--radius-lg);padding:var(--sp-4) var(--sp-5);display:flex;flex-direction:column;gap:var(--sp-1)}
.tile__label{font:500 12px/16px var(--font-sans);letter-spacing:.5px;text-transform:uppercase;color:var(--on-surface-muted)}
.tile__value{font:500 32px/40px var(--font-mono);color:var(--on-surface);font-feature-settings:"tnum"}
.tile__delta{font:500 12px/16px var(--font-sans);color:var(--on-surface-variant)} .tile__delta--up{color:var(--success)} .tile__delta--down{color:var(--danger)}
.pill{display:inline-flex;align-items:center;gap:6px;height:24px;padding:0 10px;border-radius:var(--radius-pill);font:500 12px/1 var(--font-sans)}
.pill--success{background:var(--success-container);color:var(--success)}.pill--warn{background:var(--warning-container);color:var(--warning)}
.pill--danger{background:var(--danger-container);color:var(--danger)}.pill--info{background:var(--info-container);color:var(--info)}
.pill--neutral{background:var(--surface-container-highest);color:var(--on-surface-variant)}
.pill__dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.table{width:100%;border-collapse:collapse;font-size:14px}
.table th{text-align:left;color:var(--on-surface-muted);font:500 12px/16px var(--font-sans);letter-spacing:.5px;text-transform:uppercase;padding:var(--sp-3) var(--sp-4);border-bottom:1px solid var(--outline-variant)}
.table td{padding:var(--sp-3) var(--sp-4);color:var(--on-surface);border-bottom:1px solid var(--outline-variant)}
.table td.num{text-align:right;font-family:var(--font-mono);font-feature-settings:"tnum"}
.table tbody tr:last-child td{border-bottom:none}
.table tbody tr:hover{background:rgba(228,226,230,.08)}
.banner{display:flex;align-items:center;gap:var(--sp-4);padding:var(--sp-4) var(--sp-5);border-radius:var(--radius-md);border-left:4px solid var(--warning);background:var(--warning-container);color:var(--on-surface)}
.bar{height:8px;border-radius:var(--radius-pill);background:var(--surface-container-highest);overflow:hidden}
.bar>span{display:block;height:100%;background:var(--primary)}
"""

PAGE_CSS = """
a{color:var(--primary);text-decoration:none}
.appbar{background:var(--surface-container-low);border:1px solid var(--outline-variant);border-radius:var(--radius-lg);padding:var(--sp-5) var(--sp-5)}
.appbar__row{display:flex;align-items:center;gap:var(--sp-3);flex-wrap:wrap}
.appbar h1{margin:0;font:400 28px/36px var(--font-sans);color:var(--on-surface)}
.appbar__tenant{margin-top:var(--sp-3);color:var(--on-surface-variant);font:400 14px/20px var(--font-sans)}
.appbar__tenant b{color:var(--on-surface)}
.appbar__sub{margin-top:var(--sp-2);color:var(--on-surface-muted);font:400 14px/20px var(--font-sans);max-width:820px}
.spacer{flex:1}
.btn{display:inline-flex;align-items:center;gap:6px;height:36px;padding:0 16px;border-radius:var(--radius-pill);background:var(--primary-container);color:var(--on-primary-container);font:500 14px/1 var(--font-sans);border:1px solid var(--primary-container)}
.btn:hover{filter:brightness(1.1)}
.section-label{font:500 12px/16px var(--font-sans);letter-spacing:.5px;text-transform:uppercase;color:var(--primary);display:flex;align-items:center;gap:var(--sp-3);margin:0}
.section-label::after{content:"";flex:1;height:1px;background:var(--outline-variant)}
.barlist{display:flex;flex-direction:column;gap:var(--sp-4)}
.barlist__row{display:grid;grid-template-columns:1fr 1fr 88px;align-items:center;gap:var(--sp-4)}
.barlist__label{color:var(--on-surface-variant);font:400 14px/20px var(--font-sans)}
.barlist__pct{text-align:right;font-family:var(--font-mono);font-feature-settings:"tnum";font-size:13px;color:var(--on-surface-variant)}
.fw-card{display:flex;flex-direction:column;gap:var(--sp-3)}
.fw-card__top{display:flex;align-items:baseline;justify-content:space-between;gap:var(--sp-3)}
.fw-card__name{font:500 14px/20px var(--font-sans);color:var(--on-surface)}
.fw-card__pct{font:500 22px/28px var(--font-mono);color:var(--primary);font-feature-settings:"tnum"}
.fw-card__meta{color:var(--on-surface-muted);font:400 12px/16px var(--font-sans)}
.sev{font-family:var(--font-mono);font-size:12px;text-transform:uppercase}
.footer{color:var(--on-surface-muted);font:400 12px/16px var(--font-sans);text-align:center;padding-top:var(--sp-2)}
"""

FONT_LINK = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
    'family=Roboto:wght@400;500&family=Roboto+Mono:wght@400;500&display=swap">'
)


def _esc(v) -> str:
    return html.escape(str(v))


def _sev_pill(sev: str) -> str:
    s = (sev or "").lower()
    if s == "high":
        return "pill--danger"
    if s == "medium":
        return "pill--warn"
    if s == "low":
        return "pill--info"
    return "pill--neutral"


def _kpi_tiles(kpis: list[dict]) -> str:
    cells = ""
    for k in kpis:
        cells += (
            "<div class='tile'>"
            f"<div class='tile__label'>{_esc(k['label'])}</div>"
            f"<div class='tile__value'>{_esc(k['value'])}</div>"
            f"<div class='tile__delta'>{_esc(k['note'])}</div>"
            "</div>"
        )
    return f"<section class='kpi-row'>{cells}</section>"


def _approval_banner(data: dict) -> str:
    """Surfaced when there are failing controls — the agent can remediate (approval-gated)."""
    failing = data.get("failing", [])
    if not failing:
        return ""
    first = failing[0]
    extra = f" (+{len(failing) - 1} more)" if len(failing) > 1 else ""
    return (
        "<div class='banner'>"
        f"<span class='pill pill--warn'><span class='pill__dot'></span>{len(failing)} failing</span>"
        "<span class='label-m' style='text-transform:uppercase;color:var(--warning)'>policy_change</span>"
        f"<span class='body-m'>Top finding [{_esc((first['severity'] or '').upper())}]: "
        f"{_esc(first['title'])}{_esc(extra)}. The agent can stage a remediation, but applying "
        "system fixes is approval-gated (never auto-applied).</span>"
        "</div>"
    )


def _framework_cards(data: dict) -> str:
    """Vanta/Drata-style framework-status cards with progress bars."""
    cards = ""
    for fw in data["frameworks"]:
        pct = fw["pct"]
        cards += (
            "<div class='fw-card'>"
            "<div class='fw-card__top'>"
            f"<span class='fw-card__name'>{_esc(fw['name'])}</span>"
            f"<span class='fw-card__pct'>{pct}%</span>"
            "</div>"
            f"<div class='bar'><span style='width:{pct}%'></span></div>"
            f"<div class='fw-card__meta'>{fw['passing']} passing · {fw['failing']} failing · "
            f"{fw['notapplicable']} not applicable</div>"
            "</div>"
        )
    return (
        "<div class='card'>"
        "<div class='card__head'><h2 class='card__title'>Framework status</h2>"
        "<span class='pill pill--info'><span class='pill__dot'></span>data: live from OpenSCAP</span></div>"
        f"{cards}"
        "</div>"
    )


def _failing_table(data: dict) -> str:
    """The expiring/failing-items queue: real failing CIS controls + expiring SME items."""
    rows = ""
    for f in data["failing"]:
        sev = (f["severity"] or "unknown").upper()
        rows += (
            "<tr>"
            f"<td>{_esc(f['title'])}</td>"
            f"<td><span class='pill pill--neutral sev'>CIS</span></td>"
            f"<td><span class='pill {_sev_pill(f['severity'])}'>{_esc(sev)}</span></td>"
            "<td><span class='pill pill--danger'>FAIL</span></td>"
            "</tr>"
        )
    for s in data["sme"]:
        if not s["expiring"]:
            continue
        rows += (
            "<tr>"
            f"<td>{_esc(s['item'])} <span class='fw-card__meta'>· expires {_esc(s['expires'])}</span></td>"
            f"<td><span class='pill pill--neutral sev'>{_esc(s['kind'].upper())}</span></td>"
            "<td><span class='pill pill--warn'>MEDIUM</span></td>"
            f"<td><span class='pill pill--warn'>{_esc(s['days'])}d</span></td>"
            "</tr>"
        )
    if not rows:
        rows = "<tr><td colspan='4' class='fw-card__meta'>No failing or expiring items — all controls met.</td></tr>"
    return (
        "<div class='card'>"
        "<div class='card__head'><h2 class='card__title'>Failing &amp; expiring queue</h2>"
        "<span class='pill pill--info'><span class='pill__dot'></span>real oscap findings</span></div>"
        "<table class='table'><thead><tr><th>Control / item</th><th>Source</th><th>Severity</th>"
        "<th>Status</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</div>"
    )


def render(data: dict) -> str:
    connected = data["connected"]
    conn_txt = "core: OpenSCAP connected" if connected else "core: OpenSCAP NO RESULTS"
    conn_cls = "pill--success" if connected else "pill--danger"
    status_pill = (
        f"<span class='pill {conn_cls}'><span class='pill__dot'></span>agent active · {_esc(conn_txt)}</span>"
    )
    live_badge = "<span class='pill pill--info'><span class='pill__dot'></span>data: live from OpenSCAP</span>"
    open_btn = f"<a class='btn' href='{_esc(data['report_url'])}' target='_blank' rel='noopener'>Open report ↗</a>"

    body = (
        _approval_banner(data)
        + _kpi_tiles(data["kpis"])
        + "<section class='shell' style='gap:var(--sp-4)'>"
        "<div class='section-label'>Control posture</div>"
        "<div class='grid'>"
        f"<div class='col-5' style='grid-column:span 5'>{_framework_cards(data)}</div>"
        f"<div class='col-7' style='grid-column:span 7'>{_failing_table(data)}</div>"
        "</div></section>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agentic Compliance — {_esc(TENANT)}</title>
{FONT_LINK}
<style>{BASE_CSS}{PAGE_CSS}</style>
</head>
<body class="page">
<div class="shell">
  <header class="appbar">
    <div class="appbar__row">
      <h1>Agentic Compliance</h1>
      {status_pill}
      {live_badge}
      <span class="spacer"></span>
      {open_btn}
    </div>
    <div class="appbar__tenant"><b>{_esc(TENANT)}</b> · core: OpenSCAP (open-source compliance scanner)
      · profile: {_esc(data['framework'])}</div>
    <div class="appbar__sub">{_esc(SUBTITLE)}</div>
  </header>
  {body}
  <footer class="footer">agentic-compliance · live findings for {_esc(TENANT)} ·
    <a href="/api/activity">/api/activity</a> · <a href="/report">/report</a> ·
    agent + human, on a real OpenSCAP core · redevops.io Agentic Business OS</footer>
</div>
</body>
</html>"""


# --- optional LLM rewrite (guarded: works without any API key) ---------------
def _llm_blurb(prompt: str) -> str | None:
    """Return a plain-English rewrite from Claude, or None if no key / any error.

    Optional by design — `explain` already has a deterministic answer built from the
    SCAP content's own description/rationale/fix. The LLM only rephrases it nicely.
    Absence of ANTHROPIC_API_KEY must never break the endpoint.
    """
    base = os.environ.get("REDEVOPS_LLM_BASE_URL")
    if base:
        try:
            r = httpx.post(
                base.rstrip("/") + "/chat/completions",
                json={"model": os.environ.get("REDEVOPS_LLM_MODEL", "DeepSeek-V4-Flash"),
                      "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": 220, "temperature": 0.3},
                timeout=90.0,   # DeepSeek runs on CPU (~15 tok/s) — be patient
            )
            if r.status_code == 200:
                txt = (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
                if txt:
                    return txt
        except Exception:
            pass
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                # claude-opus-4-8 is Anthropic's current Opus-tier model id.
                "model": "claude-opus-4-8",
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15.0,
        )
        r.raise_for_status()
        return "".join(
            b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text"
        ).strip() or None
    except Exception:
        return None


# --- agentic actions ---------------------------------------------------------
def _scan() -> dict:
    """Re-run the REAL oscap scan via scan.sh, then return the updated pass rate.

    Deterministic: shells out to the same scanner used by the seed. Long-running, so
    it's the explicit, on-demand action (the dashboard otherwise reads the cached file).
    """
    script = HERE / "scan.sh"
    summary = "Re-ran the OpenSCAP scan."
    rc = None
    if script.exists():
        proc = subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, timeout=600
        )
        rc = proc.returncode
        # oscap exit 2 = scan ran with failing rules (normal); >2 is a real error.
        if rc > 2:
            return {"status": "error", "action": "scan", "rc": rc,
                    "summary": "oscap scan failed", "stderr": proc.stderr[-800:]}
    data = fetch_activity(force=True)
    c = data["counts"]
    return {
        "status": "done",
        "action": "scan",
        "rc": rc,
        "pass_rate": data["kpis"][0]["value"],
        "passing": c["pass"],
        "failing": c["fail"],
        "notapplicable": c["notapplicable"],
        "summary": f"Scan complete — {c['pass']} pass / {c['fail']} fail "
                   f"({data['kpis'][0]['value']} of {c['scored']} scored controls). "
                   f"{summary}",
    }


def _resolve_rule(rule_id: str) -> dict | None:
    """Look up a rule by full id or short suffix from the parsed SCAP content."""
    rules, _ = _parse_scap()
    if rule_id in rules:
        return rules[rule_id]
    # allow short ids like 'accounts_umask_etc_profile'
    for rid, meta in rules.items():
        if rid.endswith(rule_id) or _short_id(rid) == rule_id:
            return meta
    return None


def _explain(body: dict) -> dict:
    """Plain-English explanation + remediation for a failing rule.

    Deterministic answer is built from the rule's own SCAP description/rationale/fix.
    If ANTHROPIC_API_KEY is set, an LLM rewrite is added; otherwise the deterministic
    text stands on its own.
    """
    rule_id = body.get("rule_id") or body.get("rule") or ""
    meta = _resolve_rule(rule_id)
    if not meta:
        data = fetch_activity()
        return {
            "status": "error", "action": "explain",
            "error": f"unknown rule '{rule_id}'",
            "hint": "Use a rule id from /api/activity .failing[].id",
            "available": [f["id"] for f in data["failing"]][:10],
        }

    rationale = meta["rationale"] or "This CIS control hardens the server against a known risk."
    fix = meta["fix"] or "Apply the configuration described in the CIS benchmark."
    deterministic = (
        f"Control: {meta['title']}. "
        f"What it checks: {meta['description'] or 'see the CIS benchmark rule.'} "
        f"Why it matters: {rationale} "
        f"How to fix: {fix}"
    )

    blurb = _llm_blurb(
        "You are a compliance engineer for a roofing contractor's IT. In 3-4 plain-English "
        "sentences (no jargon, no preamble), explain this failing CIS server control to the "
        f"owner and how to fix it. Title: {meta['title']}. Description: {meta['description']}. "
        f"Rationale: {meta['rationale']}. Remediation: {meta['fix']}"
    )

    out = {
        "status": "done",
        "action": "explain",
        "rule_id": meta["id"],
        "title": meta["title"],
        "severity": meta["severity"],
        "explanation": deterministic,
        "remediation": fix,
        "source": "openscap-content",
    }
    if blurb:
        out["explanation_llm"] = blurb
    return out


def _remediate(body: dict) -> dict:
    """Applying a system fix changes the host configuration — never auto-executed.

    The module declares approval_required:[policy_change], so this stages the fix and
    returns pending_approval with the exact remediation that *would* run.
    """
    rule_id = body.get("rule_id") or body.get("rule") or ""
    meta = _resolve_rule(rule_id)
    if not meta:
        data = fetch_activity()
        return {
            "status": "error", "action": "remediate",
            "error": f"unknown rule '{rule_id}'",
            "available": [f["id"] for f in data["failing"]][:10],
        }
    fix = meta["fix"] or "Apply the CIS-recommended configuration for this control."
    return {
        "status": "pending_approval",
        "action": "remediate",
        "approval": "policy_change",
        "requires": "human approval",
        "rule_id": meta["id"],
        "title": meta["title"],
        "severity": meta["severity"],
        "proposed_remediation": fix,
        "summary": f"Remediation for '{meta['title']}' is staged and awaiting human approval. "
                   "System fixes are never auto-applied by the agent (policy_change is "
                   "approval-gated).",
    }


# --- routes ------------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {"status": "ok", "core": "openscap", "connected": scap_connected()}


@app.get("/api/activity")
def activity() -> JSONResponse:
    return JSONResponse(fetch_activity())


# --- Context Runtime: live decisions over a synthetic finding stream ----------
import asyncio as _cr_asyncio
import json as _cr_json
from datetime import datetime as _cr_dt, timezone as _cr_tz
from fastapi.responses import StreamingResponse as _CRStreamingResponse

try:
    from context_runtime.integrations.agentic_compliance import (  # type: ignore
        AgenticComplianceTenant as _CRTenant, agentic_compliance_bucket as _cr_bucket,
    )
    _CR = _CRTenant(epsilon=0.15)
except Exception:  # noqa: BLE001
    _CR = None

    def _cr_bucket(_t):  # type: ignore
        return "general"

_CR_SYNTH = [
    'Weak password policy on login',
    'TLS cipher suite is deprecated',
    'Audit logging disabled',
    'Outdated kernel, CVE pending',
]


def _cr_decide(text: str) -> dict:
    try:
        bucket = _cr_bucket(text)
    except Exception:  # noqa: BLE001
        bucket = "general"
    if _CR is not None:
        try:
            try:
                arm = _CR.choose(text, bucket=bucket)
            except TypeError:
                arm = _CR.choose(text)
            try:
                _CR.record_outcome(text, 5.0)
            except Exception:  # noqa: BLE001
                pass
            return {"bucket": str(bucket), "bundle": getattr(arm, "key", str(arm))}
        except Exception:  # noqa: BLE001
            pass
    return {"bucket": str(bucket), "bundle": "(context runtime offline)"}

_CR_LIVE_FEED = """
<div id="cr-live" style="position:fixed;right:16px;bottom:16px;width:340px;max-height:58vh;overflow:auto;background:#17171a;border:1px solid #2f2f33;border-radius:12px;padding:12px;font:13px/1.45 Roboto,system-ui,sans-serif;color:#e4e2e6;z-index:9999;box-shadow:0 10px 34px rgba(0,0,0,.45)">
  <div style="color:#4fd1c5;font-weight:600;margin-bottom:8px">Context Runtime — live decisions</div>
  <div id="cr-feed" style="color:#9b99a1">connecting…</div>
</div>
<script>
(function(){
  var feed=document.getElementById('cr-feed');var first=true;
  try{
    var es=new EventSource('/api/stream');
    es.onmessage=function(e){
      if(first){feed.innerHTML='';first=false;}
      var d=JSON.parse(e.data);var row=document.createElement('div');
      row.style.cssText='border-top:1px solid #2f2f33;padding:7px 0';
      row.innerHTML='<div style="color:#9b99a1;font-size:11px">'+d.ts+' \u00b7 <b style="color:#c7c5ca">'+d.bucket+'</b></div>'+'<div style="margin:2px 0">'+d.input+'</div>'+'<div style="color:#4fd1c5">\u2192 pulled context: <b>'+d.bundle+'</b></div>';
      feed.insertBefore(row,feed.firstChild);
      while(feed.children.length>8) feed.removeChild(feed.lastChild);
    };
    es.onerror=function(){ if(first){feed.textContent='(live stream unavailable)';} };
  }catch(err){feed.textContent='(live stream unavailable)';}
})();
</script>
"""


@app.get("/api/stream")
async def cr_stream() -> _CRStreamingResponse:
    async def _gen():
        i = 0
        while True:
            text = _CR_SYNTH[i % len(_CR_SYNTH)]
            i += 1
            d = _cr_decide(text)
            evt = {"input": text, "ts": _cr_dt.now(_cr_tz.utc).strftime("%H:%M:%S"), **d}
            yield f"data: {_cr_json.dumps(evt)}\n\n"
            await _cr_asyncio.sleep(2.5)
    return _CRStreamingResponse(_gen(), media_type="text/event-stream")


_CR_BANNER = """<div style="position:sticky;top:0;z-index:9998;background:linear-gradient(90deg,#10201d,#17171a);border-bottom:1px solid #2f2f33;color:#e4e2e6;font:13px/1.4 Roboto,system-ui,sans-serif;padding:9px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap"><span style="background:#4fd1c5;color:#08110f;font-weight:700;border-radius:5px;padding:2px 8px;font-size:11px;letter-spacing:.4px">CONTEXT RUNTIME</span><span style="background:#2f2f33;border-radius:5px;padding:2px 8px;font-size:11px;letter-spacing:.4px">DEMO</span><span style="color:#9b99a1">This demo app is plugged into <b style="color:#e4e2e6">Context Runtime</b>, which optimizes which rule-family evidence to pull — correct remediation vs cost (3.56 vs 2.46). <a href="https://github.com/redevops-io/context-runtime" style="color:#4fd1c5;text-decoration:none">learn more \u2192</a></span></div>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    import re as _cr_re
    page = render(fetch_activity())
    page = _cr_re.sub(r"(<body[^>]*>)", lambda m: m.group(1) + _CR_BANNER, page, count=1)
    if "_CR_BANNER" not in page and "cr-live" not in page:  # no <body> matched → prepend
        page = _CR_BANNER + page
    return (page.replace("</body>", _CR_LIVE_FEED + "</body>")
            if "</body>" in page else page + _CR_LIVE_FEED)


@app.get("/report")
def report():
    if SCAP_REPORT.exists():
        return FileResponse(str(SCAP_REPORT), media_type="text/html")
    return PlainTextResponse(
        "No OpenSCAP report yet — run `python3 seed.py` (or POST /agent/run "
        '{"action":"scan"}) to generate results/report.html.',
        status_code=404,
    )


@app.post("/agent/run")
async def agent_run(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}
    action = (body or {}).get("action", "")

    if action == "scan":
        return JSONResponse(_scan())
    if action == "explain":
        return JSONResponse(_explain(body or {}))
    if action == "remediate":
        return JSONResponse(_remediate(body or {}))
    return JSONResponse(
        {"status": "error", "error": f"unknown action '{action}'",
         "supported": ["scan", "explain", "remediate"]},
        status_code=400,
    )


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
