#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail CI when attack_scenarios.json violates security gates."
    )
    parser.add_argument(
        "--input",
        default="artifacts/attack_scenarios.json",
        help="Path to attack_scenarios.json",
    )
    parser.add_argument(
        "--fail-on-score",
        default="high",
        help="Comma-separated scenario scores that should fail (e.g. high,critical)",
    )
    parser.add_argument(
        "--max-unmapped-check-ids",
        type=int,
        default=0,
        help="Maximum allowed unmapped check IDs before failing.",
    )
    parser.add_argument(
        "--deny-check-ids",
        default="",
        help="Comma-separated check IDs that must never appear in unmapped_check_ids.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"FAIL: missing input file: {input_path}")
        return 1

    data = json.loads(input_path.read_text(encoding="utf-8"))
    scenarios = data.get("scenarios") or []
    summary = data.get("summary") or {}
    unmapped_ids = data.get("unmapped_check_ids") or []

    fail_scores = {x.strip().lower() for x in args.fail_on_score.split(",") if x.strip()}
    deny_ids = {x.strip() for x in args.deny_check_ids.split(",") if x.strip()}

    failing_scenarios = [
        s for s in scenarios if str(s.get("score", "")).strip().lower() in fail_scores
    ]
    unmapped_count = int(summary.get("unmapped_check_ids", len(unmapped_ids)))
    denied_unmapped = sorted(deny_ids.intersection(set(unmapped_ids)))

    failed = False

    if failing_scenarios:
        failed = True
        print(
            "FAIL: blocking scenarios found:",
            [f"{s.get('id')}({s.get('score')})" for s in failing_scenarios],
        )

    if unmapped_count > args.max_unmapped_check_ids:
        failed = True
        print(
            "FAIL: unmapped_check_ids exceeded:",
            f"{unmapped_count} > {args.max_unmapped_check_ids}",
        )

    if denied_unmapped:
        failed = True
        print("FAIL: denied unmapped check IDs found:", denied_unmapped)

    if failed:
        return 1

    print("PASS: gate conditions satisfied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
