"""Command-line interface for passguard."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import List, Optional

from . import __version__
from .breach import BreachCheckError, pwned_count
from .core import analyze, apply_breach_count, generate


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
    check.add_argument(
        "--min-score",
        type=int,
        metavar="N",
        help="exit with status 1 if the score is below N (handy in scripts and CI)",
    )
    check.add_argument(
        "--breach-check",
        action="store_true",
        help="also look the password up in Have I Been Pwned; only the first 5 "
        "characters of its SHA-1 hash are sent",
    )

    gen = sub.add_parser("generate", help="generate random passwords")
    gen.add_argument("-l", "--length", type=int, default=16, help="password length (default 16)")
    gen.add_argument("-n", "--count", type=int, default=1, help="how many to generate (default 1)")
    gen.add_argument("--no-symbols", action="store_true", help="letters and digits only")
    return parser


def _print_report(result) -> None:
    print(f"Strength : {result.rating} (score {result.score}/100)")
    print(f"Entropy  : ~{result.entropy_bits} bits")
    print(f"Cracking : {result.crack_time} (offline, 10 billion guesses/s)")
    if result.breach_count is not None:
        if result.breach_count:
            print(f"Breaches : found {result.breach_count:,} times in known data breaches")
        else:
            print("Breaches : not found in known data breaches")
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

        if args.breach_check:
            try:
                apply_breach_count(result, pwned_count(password))
            except BreachCheckError as err:
                print(f"warning: breach check skipped ({err})", file=sys.stderr)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            _print_report(result)

        if args.min_score is not None and result.score < args.min_score:
            return 1
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
