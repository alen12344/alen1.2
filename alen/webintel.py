from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse, urljoin

import requests


from dataclasses import dataclass

@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    status: str
    confidence: str
    evidence: Dict[str, str]

def audit_headers_tls(target: str, timeout: int, ua: str) -> Dict[str, Any]:
    findings = []
    try:
        r = requests.get(target, timeout=timeout, headers={"User-Agent": ua}, allow_redirects=True)
        h = {k.lower(): v for k, v in r.headers.items()}

        missing = []
        for key in ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"]:
            if key not in h:
                missing.append(key)

        if missing:
            findings.append({
                "id": "HDR-001",
                "title": "Missing security headers",
                "category": "Headers",
                "severity": "medium",
                "status": "CONFIRMED",
                "confidence": "HIGH",
                "evidence": {"missing": ", ".join(missing), "url": r.url},
            })

        # robots exposure is indicator (not always vuln)
        # Keep in indicator module
        return {"findings": [Finding(**f) for f in findings]}
    except Exception as e:
        return {"findings": [Finding(
            id="HTTP-ERR",
            title="HTTP request failed",
            category="Connectivity",
            severity="info",
            status="INDICATOR",
            confidence="LOW",
            evidence={"error": str(e), "url": target},
        )]}


def crawl_same_host(target: str, timeout: int, ua: str, max_pages: int = 200) -> Dict[str, Any]:
    # Minimal safe crawler: only same host, only GET, no forms submit.
    host = urlparse(target).netloc
    seen = set()
    pages = []
    queue = [target]
    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": ua}, allow_redirects=True)
            ct = (r.headers.get("content-type") or "").lower()
            body = r.text if "text/html" in ct or "javascript" in ct else ""
            pages.append({"url": r.url, "status": r.status_code, "content_type": ct, "body": body[:200000]})
            if "text/html" in ct:
                for link in re.findall(r'href=["\']([^"\']+)["\']', body, flags=re.I):
                    nxt = urljoin(r.url, link)
                    if urlparse(nxt).netloc == host:
                        queue.append(nxt)
        except Exception:
            continue
    return {"host": host, "pages": pages, "count": len(pages)}


def discover_endpoints_from_html_js(target: str, pages: List[Dict[str, Any]], timeout: int, ua: str) -> Dict[str, Any]:
    # Extract endpoints from inline JS and linked JS (same host)
    host = urlparse(target).netloc
    endpoints = set()
    js_urls = set()

    for p in pages:
        body = p.get("body") or ""
        for m in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, flags=re.I):
            js = urljoin(p["url"], m)
            if urlparse(js).netloc == host:
                js_urls.add(js)
        # endpoints in HTML
        for m in re.findall(r'["\'](\/api\/[^"\']+|\/graphql|\/v\d+\/[^"\']+)["\']', body, flags=re.I):
            endpoints.add(m)

    # fetch JS and parse URL-like strings
    for js in list(js_urls)[:30]:
        try:
            r = requests.get(js, timeout=timeout, headers={"User-Agent": ua})
            txt = r.text
            for m in re.findall(r'["\'](\/[a-zA-Z0-9_\-\/]{3,}(\?[a-zA-Z0-9_\-=&%]+)?)["\']', txt):
                endpoints.add(m[0])
        except Exception:
            continue

    return {"js_urls": sorted(js_urls), "endpoints": sorted(endpoints)}


def detect_xss_sqli_indicators(pages: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings = []
    # Very conservative indicators: server error messages in responses
    sqli_err = re.compile(r"(SQL syntax|mysql_fetch|ORA-\d+|SQLite\/JDBC|PostgreSQL.*ERROR|Unclosed quotation mark)", re.I)
    xss_reflect = re.compile(r"<script[^>]*>.*</script>", re.I | re.S)

    for p in pages:
        body = p.get("body") or ""
        if sqli_err.search(body):
            findings.append(Finding(
                id="SQLI-IND-001",
                title="SQL error pattern detected (indicator)",
                category="Injection",
                severity="medium",
                status="INDICATOR",
                confidence="MED",
                evidence={"url": p.get("url",""), "match": "SQL error signature"},
            ))
        # XSS: only indicator if script tags appear in reflected context (very weak)
        if xss_reflect.search(body) and "?" in (p.get("url","")):
            findings.append(Finding(
                id="XSS-IND-001",
                title="Potential reflected script context (indicator)",
                category="XSS",
                severity="medium",
                status="INDICATOR",
                confidence="LOW",
                evidence={"url": p.get("url",""), "note": "Manual verification required"},
            ))
    return {"findings": findings}


def owasp_map(findings: List[Any]) -> Dict[str, Any]:
    # simple heuristic mapping
    mapping = {
        "A01:2021-Broken Access Control": [],
        "A02:2021-Cryptographic Failures": [],
        "A03:2021-Injection": [],
        "A04:2021-Insecure Design": [],
        "A05:2021-Security Misconfiguration": [],
        "A06:2021-Vulnerable and Outdated Components": [],
        "A07:2021-Identification and Authentication Failures": [],
        "A08:2021-Software and Data Integrity Failures": [],
        "A09:2021-Security Logging and Monitoring Failures": [],
        "A10:2021-SSRF": [],
    }
    for f in findings:
        cat = (f.category or "").lower()
        if "inject" in cat or "sqli" in (f.id or "").lower():
            mapping["A03:2021-Injection"].append(f.id)
        elif "headers" in cat or "misconfig" in cat:
            mapping["A05:2021-Security Misconfiguration"].append(f.id)
        elif "xss" in cat:
            mapping["A03:2021-Injection"].append(f.id)
        else:
            mapping["A05:2021-Security Misconfiguration"].append(f.id)
    return mapping


def risk_score(findings: List[Any]) -> Dict[str, Any]:
    weights = {"info": 0, "low": 20, "medium": 50, "high": 80, "critical": 100}
    score = 0
    for f in findings:
        score = max(score, weights.get((f.severity or "info").lower(), 0))
    level = "LOW"
    if score >= 80:
        level = "HIGH"
    elif score >= 50:
        level = "MEDIUM"
    return {"score": score, "level": level, "count": len(findings)}
