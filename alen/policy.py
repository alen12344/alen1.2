from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class ToolPolicy:
    enabled: bool = True
    severities: Optional[List[str]] = None
    safe_only: bool = True
    passive_only: bool = True
    fingerprint_only: bool = True


@dataclass
class Policy:
    version: str
    host_only: bool
    allow_subdomains: bool
    exclude_paths: List[str]
    rate_limit_rps: float
    timeout_http_sec: int
    max_pages: int
    user_agent: str
    nuclei: ToolPolicy
    nmap: ToolPolicy
    nikto: ToolPolicy
    wpscan: ToolPolicy
    out_dir: str
    formats: List[str]


def load_policy(path: str) -> Policy:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")
    raw: Dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    tools = raw.get("tools", {}) or {}
    rep = raw.get("reporting", {}) or {}
    scope = raw.get("scope", {}) or {}
    runtime = raw.get("runtime", {}) or {}

    def tool(name: str) -> ToolPolicy:
        t = tools.get(name, {}) or {}
        return ToolPolicy(
            enabled=bool(t.get("enabled", True)),
            severities=t.get("severities"),
            safe_only=bool(t.get("safe_only", True)),
            passive_only=bool(t.get("passive_only", True)),
            fingerprint_only=bool(t.get("fingerprint_only", True)),
        )

    return Policy(
        version=str(raw.get("version", "1.2")),
        host_only=bool(scope.get("host_only", True)),
        allow_subdomains=bool(scope.get("allow_subdomains", False)),
        exclude_paths=list(scope.get("exclude_paths", [])),
        rate_limit_rps=float(runtime.get("rate_limit_rps", 2)),
        timeout_http_sec=int(runtime.get("timeout_http_sec", 12)),
        max_pages=int(runtime.get("max_pages", 200)),
        user_agent=str(runtime.get("user_agent", "ALEN/1.2")),
        nuclei=tool("nuclei"),
        nmap=tool("nmap"),
        nikto=tool("nikto"),
        wpscan=tool("wpscan"),
        out_dir=str(rep.get("out_dir", "~/alen-report")),
        formats=list(rep.get("formats", ["html", "json", "md"])),
    )
