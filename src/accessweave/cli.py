"""Command-line entry point for AccessWeave.

Problems are reported as one-line messages instead of Python tracebacks so the
tool can be used directly in CI pipelines.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_inventory, relationship_edges

EXIT_OK = 0
EXIT_INVALID_INPUT = 1
EXIT_USAGE = 2


class InventoryFileError(Exception):
    """The inventory file is missing or cannot be read."""


class InventoryFormatError(Exception):
    """The inventory file was read but does not contain a usable inventory."""


def _load_inventory(path: Path) -> dict:
    """Read and parse an exported inventory file.

    ``utf-8-sig`` keeps files exported on Windows readable: those often carry a
    UTF-8 byte-order mark that plain ``utf-8`` decoding rejects.
    """
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InventoryFileError(
            f"cannot read inventory file {path}: {exc.strerror or exc}"
        ) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InventoryFormatError(
            f"invalid JSON in {path} at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise InventoryFormatError(f"inventory file {path} must contain a JSON object")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="accessweave",
        description="Offline identity-relationship and directory-permission review.",
    )
    parser.add_argument("inventory", type=Path, help="Exported identity inventory JSON file")
    parser.add_argument("--output", type=Path, help="Optional path for the JSON report")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with status 1 when at least one finding is reported",
    )
    args = parser.parse_args(argv)

    try:
        data = _load_inventory(args.inventory)
    except InventoryFileError as exc:
        print(f"accessweave: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except InventoryFormatError as exc:
        print(f"accessweave: {exc}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    findings = analyze_inventory(data)
    report = {
        "tool": "AccessWeave",
        "mode": "offline-inventory-review",
        "schema_version": 1,
        "findings": findings,
        "edges": relationship_edges(data),
        "notice": (
            "Findings are review hints that require human validation. "
            "No directory service was contacted and no credential was read."
        ),
    }
    text = json.dumps(report, indent=2)
    if args.output:
        try:
            args.output.write_text(text + "\n", encoding="utf-8")
        except OSError as exc:
            print(
                f"accessweave: cannot write report to {args.output}: {exc.strerror or exc}",
                file=sys.stderr,
            )
            return EXIT_INVALID_INPUT
    print(text)

    if args.fail_on_findings and findings:
        return EXIT_INVALID_INPUT
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
