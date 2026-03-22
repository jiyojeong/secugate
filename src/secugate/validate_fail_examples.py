from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

RISK_SCORES = {"low", "medium", "high", "critical"}
CHECK_ID_RE = re.compile(r"^CKV2?_AWS_\d+$")


def _strip_jsonc(text: str) -> str:
    out: list[str] = []
    in_string = False
    escaped = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < len(text) and text[i + 1] == "/":
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _load_json(path: Path, allow_jsonc: bool = False) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if allow_jsonc:
        raw = _strip_jsonc(raw)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object root")
    return data


def _load_source_index(path: Path) -> dict[str, dict[str, set[str]]]:
    source = _load_json(path, allow_jsonc=True)
    index: dict[str, dict[str, set[str]]] = {}
    for key, value in source.items():
        if not CHECK_ID_RE.match(key) or not isinstance(value, list):
            continue
        resources: set[str] = set()
        descriptions: set[str] = set()
        for i in range(0, len(value), 2):
            resource = str(value[i]).strip() if i < len(value) else ""
            description = str(value[i + 1]).strip() if i + 1 < len(value) else ""
            if resource:
                resources.add(resource)
            if description:
                descriptions.add(description)
        index[key] = {"resources": resources, "descriptions": descriptions}
    return index


def _validate_examples(
    examples_path: Path,
    require_filled: bool,
    max_errors_to_print: int,
) -> tuple[int, int]:
    data = _load_json(examples_path)
    checks = data.get("checks")
    if not isinstance(checks, list):
        print("ERROR: 'checks' must be a list")
        return 1, 0

    source_index: dict[str, dict[str, set[str]]] = {}
    source_path_value = data.get("source")
    if isinstance(source_path_value, str) and source_path_value.strip():
        source_path = Path(source_path_value)
        if source_path.is_file():
            try:
                source_index = _load_source_index(source_path)
            except Exception as exc:  # pragma: no cover
                print(f"WARN: failed to load source mapping '{source_path}': {exc}")
        else:
            print(f"WARN: source mapping file not found: {source_path}")

    errors = 0
    warnings = 0
    suppressed_errors = 0

    def emit_error(message: str) -> None:
        nonlocal errors, suppressed_errors
        errors += 1
        if errors <= max_errors_to_print:
            print(f"ERROR: {message}")
        else:
            suppressed_errors += 1

    for check_idx, check in enumerate(checks):
        label = f"checks[{check_idx}]"
        if not isinstance(check, dict):
            emit_error(f"{label} must be an object")
            continue

        check_id = str(check.get("check_id", "")).strip()
        if not CHECK_ID_RE.match(check_id):
            emit_error(f"{label}.check_id invalid: {check_id!r}")
            continue

        examples = check.get("examples")
        if not isinstance(examples, list) or not examples:
            emit_error(f"{label}.examples must be a non-empty list")
            continue

        seen_resource_ids: set[str] = set()
        source_item = source_index.get(check_id)

        for ex_idx, ex in enumerate(examples):
            ex_label = f"{label}.examples[{ex_idx}]"
            if not isinstance(ex, dict):
                emit_error(f"{ex_label} must be an object")
                continue

            required_keys = [
                "resource_type",
                "resource_id",
                "description",
                "terraform_fail_hcl",
                "why_fails",
                "attack_path",
                "risk_score",
                "mitigation",
            ]
            for key in required_keys:
                if key not in ex:
                    emit_error(f"{ex_label} missing key '{key}'")

            resource_type = str(ex.get("resource_type", "")).strip()
            resource_id = str(ex.get("resource_id", "")).strip()
            description = str(ex.get("description", "")).strip()
            terraform_fail_hcl = str(ex.get("terraform_fail_hcl", "")).strip()
            why_fails = str(ex.get("why_fails", "")).strip()
            attack_path = str(ex.get("attack_path", "")).strip()
            risk_score = str(ex.get("risk_score", "")).strip().lower()
            mitigation = str(ex.get("mitigation", "")).strip()

            if not resource_type:
                emit_error(f"{ex_label}.resource_type is empty")
            if not resource_id:
                emit_error(f"{ex_label}.resource_id is empty")
            elif resource_id in seen_resource_ids:
                emit_error(f"{ex_label}.resource_id duplicated: {resource_id}")
            else:
                seen_resource_ids.add(resource_id)

            if not description:
                emit_error(f"{ex_label}.description is empty")
            if not terraform_fail_hcl:
                emit_error(f"{ex_label}.terraform_fail_hcl is empty")
            if not why_fails:
                emit_error(f"{ex_label}.why_fails is empty")

            if require_filled:
                if not attack_path:
                    emit_error(f"{ex_label}.attack_path is empty")
                if not risk_score:
                    emit_error(f"{ex_label}.risk_score is empty")
                if not mitigation:
                    emit_error(f"{ex_label}.mitigation is empty")

            if risk_score and risk_score not in RISK_SCORES:
                emit_error(
                    f"{ex_label}.risk_score must be one of {sorted(RISK_SCORES)}: {risk_score!r}"
                )

            if source_item:
                if resource_type and resource_type not in source_item["resources"]:
                    emit_error(
                        f"{ex_label}.resource_type not in source mapping for {check_id}: {resource_type}"
                    )
                if description and description not in source_item["descriptions"]:
                    emit_error(
                        f"{ex_label}.description not in source mapping for {check_id}"
                    )
            else:
                warnings += 1

    if suppressed_errors:
        print(f"... suppressed {suppressed_errors} additional errors")
    print(
        f"Validation complete: checks={len(checks)} errors={errors} warnings={warnings} "
        f"mode={'require-filled' if require_filled else 'structure-only'}"
    )
    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate rules/checkov_fail_examples.json consistency"
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=Path("src/secugate/rules/checkov_fail_examples.json"),
        help="Path to checkov fail examples JSON",
    )
    parser.add_argument(
        "--require-filled",
        action="store_true",
        help="Require attack_path/risk_score/mitigation to be non-empty",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=200,
        help="Maximum number of error lines to print before summarizing",
    )
    args = parser.parse_args()

    if not args.file.is_file():
        print(f"ERROR: file not found: {args.file}")
        return 1

    errors, _ = _validate_examples(
        args.file,
        require_filled=args.require_filled,
        max_errors_to_print=max(1, args.max_errors),
    )
    return 1 if errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
