from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .runner import run_scan

console = Console()

MENU = [
    ("1", "Quick Scan (safe)", "quick"),
    ("2", "Full Scan (nuclei + nmap + nikto + wpscan)", "full"),
    ("3", "Strict Mode (CONFIRMED only)", "strict"),
    ("4", "XSS & SQLi Indicators (passive)", "indicators"),
    ("5", "Security Header & TLS Audit", "headers"),
    ("6", "Attack Surface Map + Reports", "surface"),
    ("7", "OWASP Top 10 Mapping + Reports", "owasp"),
    ("8", "Risk Score (application) + Reports", "risk"),
    ("9", "Trend Compare (scan1 vs scan2)", "trend"),
    ("10", "Export Report (HTML / SOC / JSON)", "export"),
    ("11", "Edit Policy (open alen.yml)", "policy"),
    ("12", "Exit", "exit"),
]


def run_menu(target: str, policy_path: str) -> int:
    header = Text("ALEN 1.2 — Authorized Web Audit (low FP)\n", style="bold cyan")
    header.append("evidence-first • correlation • scope tight", style="cyan")
    console.print(Panel(header, title="🧿 ALEN MENU", border_style="cyan"))

    for k, label, _ in MENU:
        console.print(f"[bold]{k}.[/bold] {label}")

    choice = console.input("\nPilih nomor (1-12): ").strip()
    if not choice:
        return 0

    # Map choice
    mode = dict((k, m) for k, _, m in MENU).get(choice, None)
    if mode in (None, "exit"):
        return 0

    if mode == "policy":
        console.print(f"Edit policy: {policy_path}")
        console.print("Gunakan editor favorit, misal: nano alen.yml")
        return 0

    strict = False
    if mode == "strict":
        strict = True
        scan_mode = "full"
    elif mode == "quick":
        scan_mode = "quick"
    else:
        # For specialized modes we still run quick pipeline but filter modules
        scan_mode = "quick"

    return run_scan(target=target, policy_path=policy_path, out_dir=None, mode=scan_mode, strict=strict, baseline=None)
