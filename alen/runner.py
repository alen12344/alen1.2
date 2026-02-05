from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from .policy import load_policy
from .reporting import write_reports
from .webintel import (
    audit_headers_tls,
    discover_endpoints_from_html_js,
    crawl_same_host,
    detect_xss_sqli_indicators,
    owasp_map,
    risk_score,
)

console = Console()


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    status: str  # CONFIRMED or INDICATOR
    confidence: str  # LOW/MED/HIGH
    evidence: Dict[str, str]


def _normalize_target(target: str) -> str:
    if not re.match(r"^https?://", target):
        target = "https://" + target
    return target.rstrip("/")


def _mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _run_cmd(cmd: List[str], timeout: int = 120) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def run_scan(
    target: str,
    policy_path: str,
    out_dir: Optional[str],
    mode: str,
    strict: bool,
    baseline: Optional[str],
) -> int:
    pol = load_policy(policy_path)
    target = _normalize_target(target)
    u = urlparse(target)
    if not u.scheme or not u.netloc:
        console.print("[red]Target URL tidak valid.[/red]")
        return 2

    # output directory
    root_out = Path(os.path.expanduser(out_dir or pol.out_dir))
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = root_out / f"alen-report-{ts}"
    evidence_dir = out / "evidence"
    _mkdir(evidence_dir)

    findings: List[Finding] = []
    meta: Dict[str, str] = {
        "tool": "ALEN",
        "version": "1.2.0",
        "target": target,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "mode": mode,
        "strict": str(strict),
    }

    # Internal web intel
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        t1 = progress.add_task("HTTP/TLS + Security Headers audit", total=1)
        headers_res = audit_headers_tls(target, timeout=pol.timeout_http_sec, ua=pol.user_agent)
        progress.advance(t1)

        t2 = progress.add_task("Crawl same-host (attack surface)", total=1)
        crawl = crawl_same_host(target, timeout=pol.timeout_http_sec, ua=pol.user_agent, max_pages=pol.max_pages)
        progress.advance(t2)

        t3 = progress.add_task("JS/HTML endpoint discovery", total=1)
        endpoints = discover_endpoints_from_html_js(target, crawl.get("pages", []), timeout=pol.timeout_http_sec, ua=pol.user_agent)
        progress.advance(t3)

        t4 = progress.add_task("Indicator checks (XSS/SQLi passive)", total=1)
        indicators = detect_xss_sqli_indicators(crawl.get("pages", []))
        progress.advance(t4)

    # Convert internal results -> findings
    findings.extend(headers_res.get("findings", []))
    findings.extend(indicators.get("findings", []))

    # Optional: external tools (safe)
    external_logs: Dict[str, str] = {}
    if mode == "full":
        if pol.nuclei.enabled:
            external_logs["nuclei"] = _run_cmd(["nuclei", "-u", target, "-severity", ",".join(pol.nuclei.severities or ["medium","high","critical"]), "-silent"], timeout=180)
        if pol.nmap.enabled:
            # safe-only scan: service detection light
            external_logs["nmap"] = _run_cmd(["nmap", "-sV", "-Pn", "-T3", u.hostname], timeout=180)
        if pol.nikto.enabled:
            external_logs["nikto"] = _run_cmd(["nikto", "-h", target], timeout=180)
        if pol.wpscan.enabled:
            external_logs["wpscan"] = _run_cmd(["wpscan", "--url", target, "--enumerate", "vp,vt,tt", "--no-update"], timeout=180)

    # Correlation (very conservative)
    # We only mark CONFIRMED when we have internal evidence + stable replay check.
    confirmed: List[Finding] = []
    for f in findings:
        if strict and f.status != "CONFIRMED":
            continue
        confirmed.append(f)

    # OWASP mapping + risk score
    mapping = owasp_map(confirmed)
    score = risk_score(confirmed)

    # Write reports + evidence
    write_reports(
        out_dir=out,
        meta=meta,
        findings=[asdict(f) for f in confirmed],
        crawl=crawl,
        endpoints=endpoints,
        owasp=mapping,
        risk=score,
        external_logs=external_logs,
        baseline_dir=baseline,
    )

    console.print(f"\n[green]Done[/green] Output folder: {out}")
    console.print("Files: report.html, summary.md, findings.json, attack-surface.md, owasp-mapping.md, verification-checklist.md, soc-quick.json, risk-score.json")
    return 0
