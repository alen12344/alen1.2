from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _merkle_root(hashes: List[str]) -> str:
    if not hashes:
        return _sha256_bytes(b"")
    layer = [bytes.fromhex(x) for x in hashes]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i+1] if i+1 < len(layer) else layer[i]
            nxt.append(hashlib.sha256(a + b).digest())
        layer = nxt
    return layer[0].hex()


def write_reports(
    out_dir: Path,
    meta: Dict[str, Any],
    findings: List[Dict[str, Any]],
    crawl: Dict[str, Any],
    endpoints: Dict[str, Any],
    owasp: Dict[str, Any],
    risk: Dict[str, Any],
    external_logs: Dict[str, str],
    baseline_dir: Optional[str],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = out_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # Core artifacts
    _write_json(out_dir / "findings.json", {"meta": meta, "findings": findings})
    _write_json(out_dir / "risk-score.json", risk)
    _write_json(out_dir / "soc-quick.json", {"meta": meta, "risk": risk, "findings": findings[:200]})
    _write(out_dir / "summary.md", _build_summary(meta, findings, risk))
    _write(out_dir / "attack-surface.md", _build_attack_surface(meta, crawl, endpoints))
    _write(out_dir / "owasp-mapping.md", _build_owasp(meta, owasp, findings))
    _write(out_dir / "verification-checklist.md", _build_verification_checklist())

    # External logs
    if external_logs:
        logs_dir = out_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        for k, v in external_logs.items():
            _write(logs_dir / f"{k}.log", v)

    # Evidence manifest
    manifest_items = []
    for p in sorted(out_dir.glob("*")):
        if p.is_file():
            b = p.read_bytes()
            manifest_items.append({"file": p.name, "sha256": _sha256_bytes(b), "bytes": len(b)})

    hashes = [i["sha256"] for i in manifest_items]
    root = _merkle_root(hashes)
    _write_json(evidence_dir / "manifest.json", {"generated": datetime.now().isoformat(timespec="seconds"), "items": manifest_items})
    _write(evidence_dir / "merkle_root.txt", root + "\n")

    # HTML report
    _write(out_dir / "report.html", _build_html(meta, findings, risk, owasp))


def _build_summary(meta: Dict[str, Any], findings: List[Dict[str, Any]], risk: Dict[str, Any]) -> str:
    top = "\n".join([f"- **{f['severity'].upper()}** {f['title']} ({f['status']}) — {f.get('evidence', {}).get('url','')}"
                     for f in findings[:10]])
    return f"""# ALEN Summary

- Target: **{meta.get('target')}**
- Time: **{meta.get('timestamp')}**
- Mode: **{meta.get('mode')}**
- Risk: **{risk.get('level')}** (score {risk.get('score')})

## Top findings
{top if top else "- (no findings)"}

## Notes
- **INDICATOR** = sinyal pasif; perlu verifikasi manual.
- **CONFIRMED** = bukti cukup kuat dari checks internal.
"""


def _build_attack_surface(meta: Dict[str, Any], crawl: Dict[str, Any], endpoints: Dict[str, Any]) -> str:
    host = crawl.get("host")
    pages = crawl.get("pages", [])
    eps = endpoints.get("endpoints", [])
    lines = [f"# Attack Surface\n\nTarget: **{meta.get('target')}**\nHost: **{host}**\n",
             "## Pages (sample)\n"]
    for p in pages[:50]:
        lines.append(f"- {p.get('status')} {p.get('url')}")
    lines.append("\n## Endpoints (JS/HTML extracted)\n")
    for e in eps[:200]:
        lines.append(f"- {e}")
    # Mermaid graph
    lines.append("\n## Visual map (Mermaid)\n")
    lines.append("```mermaid\ngraph TD\n")
    lines.append(f'  Internet["Internet"] --> App["{host}"]\n')
    lines.append("  App --> Headers[\"Headers\"]\n  App --> Exposure[\"Exposure\"]\n")
    lines.append("```\n")
    return "\n".join(lines)


def _build_owasp(meta: Dict[str, Any], owasp: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    out = [f"# OWASP Top 10 Mapping (2021)\n\nTarget: **{meta.get('target')}**\n"]
    for k, ids in owasp.items():
        out.append(f"## {k}\n")
        if not ids:
            out.append("- (none)\n")
        else:
            for i in ids:
                out.append(f"- {i}\n")
    return "\n".join(out)


def _build_verification_checklist() -> str:
    return """# Manual Verification Checklist (legal)

> Checklist ini membantu kamu mengubah **INDICATOR** menjadi **CONFIRMED** secara aman.

- [ ] Pastikan scope & izin tertulis (authorization)
- [ ] Reproduce dengan request yang sama (tanpa payload destruktif)
- [ ] Ambil evidence (status code, headers, excerpt body)
- [ ] Validasi false positive (cache, WAF, redirect)
- [ ] Catat dampak bisnis (risk)
- [ ] Rekomendasi mitigasi + referensi
"""


def _build_html(meta: Dict[str, Any], findings: List[Dict[str, Any]], risk: Dict[str, Any], owasp: Dict[str, Any]) -> str:
    rows = "\n".join(
        f"<tr><td>{f['severity']}</td><td>{f['status']}</td><td>{f.get('confidence','')}</td><td>{f['category']}</td><td>{f['title']}</td><td>{(f.get('evidence',{}).get('url',''))}</td></tr>"
        for f in findings
    )
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ALEN Report</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,Arial;margin:24px}}
h1{{margin:0 0 8px}}
.badge{{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid #ddd;margin-right:8px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th,td{{border:1px solid #eee;padding:8px;vertical-align:top}}
th{{background:#fafafa;text-align:left}}
.small{{color:#666;font-size:12px}}
</style>
</head>
<body>
<h1>🧿 ALEN 1.2 Report</h1>
<div class="small">Target: {meta.get('target')} • Time: {meta.get('timestamp')} • Mode: {meta.get('mode')}</div>
<p>
<span class="badge">Risk: {risk.get('level')} ({risk.get('score')})</span>
<span class="badge">Findings: {len(findings)}</span>
</p>

<h2>Findings</h2>
<table>
<thead><tr><th>Sev</th><th>Status</th><th>Confidence</th><th>Category</th><th>Title</th><th>Evidence</th></tr></thead>
<tbody>
{rows if rows else "<tr><td colspan='6'>(no findings)</td></tr>"}
</tbody>
</table>

<h2>OWASP Mapping (2021)</h2>
<ul>
{''.join(f"<li><b>{k}</b>: {', '.join(v) if v else '(none)'}</li>" for k,v in owasp.items())}
</ul>

<p class="small">
INDICATOR = sinyal pasif, perlu verifikasi manual. CONFIRMED = bukti cukup kuat dari checks internal.
</p>
</body>
</html>"""
