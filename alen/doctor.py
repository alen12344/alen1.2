from __future__ import annotations

import shutil
import sys

from rich.console import Console
from rich.table import Table

console = Console()


def _which(cmd: str) -> str:
    return shutil.which(cmd) or ""


def run_doctor() -> int:
    table = Table(title="ALEN Doctor (preflight)")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Hint")

    # Python
    table.add_row("Python", "OK", sys.version.split()[0])

    # Optional tools
    for tool, hint in [
        ("nuclei", "Install: sudo apt install nuclei OR go install ..."),
        ("nmap", "Install: sudo apt install nmap"),
        ("nikto", "Install: sudo apt install nikto"),
        ("wpscan", "Install: sudo apt install wpscan (optional)"),
    ]:
        path = _which(tool)
        table.add_row(tool, "OK" if path else "MISSING", path if path else hint)

    console.print(table)
    console.print("[bold]Tip:[/bold] Tool eksternal bersifat opsional. ALEN tetap jalan tanpa mereka.")
    return 0
