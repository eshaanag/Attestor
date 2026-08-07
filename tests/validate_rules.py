#!/usr/bin/env python3
"""Validate Attestor rule YAML files against schema/rule_schema.json.

Behaviour:
  * Validates every rules/**/*.yaml against the schema (real rule packs).
  * Runs a self-test over tests/fixtures/ to prove the schema accepts the
    valid fixture and rejects the two invalid ones.
  * Exit code 0 only if all real rules pass AND every fixture resolves as
    expected; non-zero otherwise.

Requires: pyyaml, jsonschema.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML not installed. Run: pip install pyyaml")

try:
    from jsonschema import Draft7Validator
except ImportError:
    sys.exit("ERROR: jsonschema not installed. Run: pip install jsonschema")

import json

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema" / "rule_schema.json"
RULES_DIR = REPO_ROOT / "rules"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

# Expected fixture outcomes: filename -> should_be_valid
FIXTURE_EXPECTATIONS = {
    "valid_example.yaml": True,
    "invalid_missing_field.yaml": False,
    "invalid_bad_id.yaml": False,
}


def load_validator() -> Draft7Validator:
    with SCHEMA_PATH.open(encoding="utf-8") as fh:
        schema = json.load(fh)
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def format_errors(validator: Draft7Validator, doc) -> list[str]:
    """Return clear, field-pointed error strings for a document (empty if valid)."""
    msgs = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        msgs.append(f"field '{loc}': {err.message}")
    return msgs


def validate_file(validator: Draft7Validator, path: Path):
    """Return (is_valid, errors). YAML/parse problems count as invalid."""
    try:
        with path.open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        return False, [f"YAML parse error: {exc}"]
    if doc is None:
        return False, ["file is empty"]
    errors = format_errors(validator, doc)
    return (len(errors) == 0), errors


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"ERROR: schema not found at {SCHEMA_PATH}")
        return 2

    validator = load_validator()
    print(f"Schema: {SCHEMA_PATH.relative_to(REPO_ROOT)}")

    # --- Real rule packs ---------------------------------------------------
    rule_files = sorted(RULES_DIR.glob("**/*.yaml"))
    print(f"\n=== Real rules (rules/**/*.yaml) ===")
    real_failures = 0
    if not rule_files:
        print("0 rules found — nothing to validate (this is fine for now).")
    else:
        for path in rule_files:
            rel = path.relative_to(REPO_ROOT)
            ok, errors = validate_file(validator, path)
            if ok:
                print(f"  PASS  {rel}")
            else:
                real_failures += 1
                print(f"  FAIL  {rel}")
                for msg in errors:
                    print(f"          - {msg}")

    # --- Fixture self-test -------------------------------------------------
    print(f"\n=== Fixture self-test (tests/fixtures/) ===")
    fixture_mismatches = 0
    for name, should_be_valid in FIXTURE_EXPECTATIONS.items():
        path = FIXTURES_DIR / name
        if not path.exists():
            fixture_mismatches += 1
            print(f"  MISSING  {name} (expected present)")
            continue
        ok, errors = validate_file(validator, path)
        expectation = "valid" if should_be_valid else "invalid"
        actual = "valid" if ok else "invalid"
        if ok == should_be_valid:
            print(f"  OK    {name}: expected {expectation}, got {actual}")
            if not ok:
                for msg in errors:
                    print(f"          - {msg}")
        else:
            fixture_mismatches += 1
            print(f"  WRONG {name}: expected {expectation}, got {actual}")
            for msg in errors:
                print(f"          - {msg}")

    # --- Summary + exit ----------------------------------------------------
    print("\n=== Summary ===")
    print(f"Real rules: {len(rule_files)} checked, {real_failures} failed.")
    print(f"Fixtures:   {len(FIXTURE_EXPECTATIONS)} checked, {fixture_mismatches} unexpected.")

    exit_code = 0 if (real_failures == 0 and fixture_mismatches == 0) else 1
    print(f"Exit code: {exit_code}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
