from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .doctor import run_doctor
from .menu import run_menu
from .runner import run_scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="alen",
        description="ALEN 1.2 — Legal-first web & network security audit (low false positives)",
    )
    p.add_argument("--target", help="Target URL (e.g. https://example.com)")
    p.add_argument("--policy", default="alen.yml", help="Path to policy yaml (default: alen.yml)")
    p.add_argument("--out", default=None, help="Output directory override (default: policy reporting.out_dir)")
    p.add_argument("--i-have-authorization", action="store_true", help="Required: confirm you have explicit permission")

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--menu", action="store_true", help="Open interactive menu (TUI)")
    mode.add_argument("--quick", action="store_true", help="Quick scan (safe)")
    mode.add_argument("--full", action="store_true", help="Full scan (uses optional external tools)")

    p.add_argument("--strict", action="store_true", help="Prefer CONFIRMED only (may miss indicators)")
    p.add_argument("--baseline", default=None, help="Baseline report dir for trend compare (optional)")
    p.add_argument("command", nargs="?", default=None, help="Subcommand: doctor")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    # subcommand
    if args.command == "doctor":
        return run_doctor()

    if not args.i_have_authorization:
        print("❌ Wajib: pakai flag --i-have-authorization (legal-first).")
        return 2

    if args.menu:
        if not args.target:
            print("Target kosong. Isi alen.yml atau pakai --target.")
            return 2
        return run_menu(target=args.target, policy_path=args.policy)

    # non-menu modes
    if not args.target:
        print("Target kosong. Pakai --target https://example.com")
        return 2

    scan_mode = "quick" if args.quick else ("full" if args.full else "quick")
    return run_scan(
        target=args.target,
        policy_path=args.policy,
        out_dir=args.out,
        mode=scan_mode,
        strict=args.strict,
        baseline=args.baseline,
    )


if __name__ == "__main__":
    raise SystemExit(main())
