"""Command-line interface for passguard."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import List, Optional

from . import __version__
from .core import analyze, generate


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passguard",
        description="Offline password strength analyzer and generator.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="analyze a password (read securely, never from arguments)")
    check.add_argument("--stdin", action="store_true", help="read the password from standard input")
    check.add_argument("--json", action="store_true", help="print the result as JSON")

    gen = sub.add_parser("generate", help="generate random passwords")
    gen.add_argument("-l", "--length", type=int, default=16, help="password length (default 16)")
    gen.add_argument("-n", "--count", type=int, default=1, help="how many to generate (default 1)")
    gen.add_argument("--no-symbols", action="store_true", help="letters and digits only")
    return parser


def _print_report(result) -> None:
    print(f"Strength : {result.rating} (score {result.score}/100)")
    print(f"Entropy  : ~{result.entropy_bits} bits")
    print(f"Cracking : {result.crack_time} (offline, 10 billion guesses/s)")
    if result.issues:
        print("Issues:")
        for item in result.issues:
            print(f"  - {item}")
    if result.suggestions:
        print("Suggestions:")
        for item in result.suggestions:
            print(f"  - {item}")


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "check":
        if args.stdin:
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass("Password to check (input hidden): ")
        result = analyze(password)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            _print_report(result)
        return 0

    if args.command == "generate":
        try:
            for _ in range(max(args.count, 1)):
                print(generate(args.length, symbols=not args.no_symbols))
        except ValueError as err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
