#!/usr/bin/env python3
"""Phishing email analyzer with human-in-the-loop escalation gate.

Run directly:
    python main.py suspicious.eml
    python main.py suspicious.eml --json

Or via the root launcher (project root):
    python main.py suspicious.eml
"""

import argparse
import json
import sys

from analyzer import analyze_email
from skill import PhishingVerdict, format_report, judge_email


def _prompt_confirm(question: str) -> bool:
    try:
        answer = input(question).strip().lower()
        return answer == "y"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _show_actions(verdict: PhishingVerdict) -> None:
    if not verdict.recommended_actions:
        print("\nNo specific actions recommended.")
        return
    print("\nRecommended actions for YOU to take (none have been done automatically):")
    for i, action in enumerate(verdict.recommended_actions, 1):
        print(f"  {i}. {action}")


def _interactive_flow(verdict: PhishingVerdict) -> None:
    print(format_report(verdict))

    if verdict.verdict == "UNCERTAIN":
        print()
        if _prompt_confirm(
            "The system is uncertain. Would you like to see the recommended actions "
            "for flagging this email for manual review? [y/N]: "
        ):
            _show_actions(verdict)
        else:
            print("\nNo action taken. Re-run with a more complete .eml file if possible.")

    elif verdict.verdict == "PHISHING":
        print()
        if _prompt_confirm(
            "⚠  This email appears to be phishing. "
            "Would you like to see the recommended escalation steps? [y/N]: "
        ):
            _show_actions(verdict)
        else:
            print("\nNo action taken. The email has NOT been reported or deleted.")

    else:  # NOT_PHISHING
        print("\nNo escalation required based on available evidence.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze a raw .eml file for phishing indicators. "
            "All escalation actions require explicit human confirmation."
        )
    )
    parser.add_argument("email_file", help="Path to a raw .eml file.")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output raw JSON verdict (skips interactive prompts).",
    )
    args = parser.parse_args()

    try:
        with open(args.email_file, "r", encoding="utf-8", errors="replace") as fh:
            raw_email = fh.read()
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        sys.exit(1)

    if not raw_email.strip():
        print("Error: email file is empty.", file=sys.stderr)
        sys.exit(1)

    print("Stage 1/2 — Extracting technical indicators...", file=sys.stderr)
    analysis = analyze_email(raw_email)

    print("Stage 2/2 — Running AI analysis...", file=sys.stderr)
    verdict = judge_email(analysis)

    if args.json_output:
        print(json.dumps(verdict.model_dump(), indent=2))
        return

    _interactive_flow(verdict)


if __name__ == "__main__":
    main()
