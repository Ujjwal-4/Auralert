#!/usr/bin/env python3
"""CLI demonstration tool for AURALERT detection engine."""

import sys

from auralert.detection.message_analyzer import analyze_message


def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: python -m auralert.detection.demo "<suspicious message or link>"')
        sys.exit(1)

    input_text = sys.argv[1]
    result = analyze_message(input_text)

    print("=" * 60)
    print("AURALERT Detection Analysis Result")
    print("=" * 60)
    print(f"Input: {input_text}")
    print(f"Verdict: {result['verdict'].upper()}")
    print(f"Risk Score: {result['risk_score']} / 100")
    print(f"Category: {result['category']}")
    print("-" * 60)
    print(f"Red Flags Detected ({len(result['red_flags'])}):")
    for flag in result["red_flags"]:
        print(f"  [{flag['code']}]: {flag['evidence']}")
        print(f"    Explanation: {flag['explanation']}")
    print("-" * 60)
    print(f'Alexa Spoken Summary: "{result["speak"]}"')
    print("=" * 60)


if __name__ == "__main__":
    main()
