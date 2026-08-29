#!/usr/bin/env python3
"""Generate the normalized 2025 CVE dataset used by CVE Finder.

The script reads the official CVE JSON records without modifying them and writes
four deterministic RFC 4180-compatible CSV files. It uses only Python's standard
library.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


EXPECTED_TOTAL = 45_206
EXPECTED_STATE_COUNTS = {"PUBLISHED": 43_426, "REJECTED": 1_780}
EXPECTED_RELATION_COUNTS = {
    "vendors": 38_385,
    "products": 68_295,
    "replacements": 37,
}

PLACEHOLDERS = frozenset(
    {
        "n/a",
        "unknown",
        "unspecified",
        "not applicable",
        "none",
        "null",
        "-",
        "*",
    }
)

CVE_ID_PATTERN = re.compile(r"^CVE-(\d{4})-(\d+)$")

CVES_FIELDS = (
    "cve_id",
    "state",
    "description_en",
    "title",
    "rejection_reason_en",
)
VENDOR_FIELDS = ("cve_id", "vendor")
PRODUCT_FIELDS = ("cve_id", "product")
REPLACEMENT_FIELDS = ("cve_id", "replaced_by")


class ValidationError(RuntimeError):
    """Raised when source data or generated CSVs violate an invariant."""


@dataclass(frozen=True)
class NormalizedCve:
    cve_id: str
    state: str
    description_en: str
    title: str
    rejection_reason_en: str
    vendors: tuple[str, ...]
    products: tuple[str, ...]
    replacements: tuple[str, ...]


def clean_text(value: Any) -> str:
    """Return a trimmed string, or an empty string for a non-string value."""

    return value.strip() if isinstance(value, str) else ""


def is_valid_name(value: Any) -> bool:
    """Return whether a vendor/product value is usable."""

    text = clean_text(value)
    return bool(text) and text.casefold() not in PLACEHOLDERS


def encode_single_line_text(value: str) -> str:
    """Encode text reversibly so it contains no physical line breaks.

    Backslashes are escaped first, preserving the distinction between an
    original literal ``\n`` and a line break encoded as ``\n``.
    """

    return (
        value.replace("\\", "\\\\")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", "\\n")
    )


def unique_valid_names(affected: Sequence[Any], field: str) -> tuple[str, ...]:
    """Collect distinct valid names from affected, case-insensitively."""

    by_normalized_name: dict[str, str] = {}
    for entry in affected:
        if not isinstance(entry, Mapping):
            continue
        value = entry.get(field)
        if not is_valid_name(value):
            continue
        text = clean_text(value)
        by_normalized_name.setdefault(text.casefold(), text)

    return tuple(
        value
        for _, value in sorted(
            by_normalized_name.items(), key=lambda item: (item[0], item[1])
        )
    )


def first_english_value(items: Any, *, source: Path, field: str) -> str:
    """Return the first non-empty English value from a CVE language list."""

    if not isinstance(items, list):
        return ""

    for item in items:
        if not isinstance(item, Mapping):
            continue
        language = clean_text(item.get("lang")).casefold()
        value = clean_text(item.get("value"))
        if language.startswith("en") and value:
            return value

    return ""


def unique_replacements(value: Any, *, source: Path) -> tuple[str, ...]:
    """Validate and normalize an optional replacedBy list."""

    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValidationError(f"{source}: containers.cna.replacedBy is not a list")

    by_id: dict[str, str] = {}
    for replacement in value:
        replacement_id = clean_text(replacement)
        if not CVE_ID_PATTERN.fullmatch(replacement_id):
            raise ValidationError(
                f"{source}: invalid replacedBy CVE ID {replacement!r}"
            )
        by_id.setdefault(replacement_id.casefold(), replacement_id)

    return tuple(
        replacement
        for _, replacement in sorted(by_id.items(), key=lambda item: item[0])
    )


def require_mapping(value: Any, *, source: Path, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{source}: {field} is not an object")
    return value


def normalize_record(payload: Any, source: Path) -> NormalizedCve:
    """Convert one official CVE JSON record to the normalized representation."""

    root = require_mapping(payload, source=source, field="root")
    metadata = require_mapping(
        root.get("cveMetadata"), source=source, field="cveMetadata"
    )
    containers = require_mapping(
        root.get("containers"), source=source, field="containers"
    )
    cna = require_mapping(containers.get("cna"), source=source, field="containers.cna")

    cve_id = clean_text(metadata.get("cveId"))
    match = CVE_ID_PATTERN.fullmatch(cve_id)
    if match is None or match.group(1) != "2025":
        raise ValidationError(f"{source}: invalid 2025 CVE ID {cve_id!r}")

    state = clean_text(metadata.get("state"))
    if state not in EXPECTED_STATE_COUNTS:
        raise ValidationError(f"{source}: unsupported state {state!r}")

    replacements = unique_replacements(cna.get("replacedBy"), source=source)

    if state == "PUBLISHED":
        affected = cna.get("affected")
        if not isinstance(affected, list):
            raise ValidationError(f"{source}: PUBLISHED CVE has no affected list")

        description = first_english_value(
            cna.get("descriptions"), source=source, field="descriptions"
        )
        if not description:
            raise ValidationError(
                f"{source}: PUBLISHED CVE has no valid English description"
            )

        return NormalizedCve(
            cve_id=cve_id,
            state=state,
            description_en=description,
            title=clean_text(cna.get("title")),
            rejection_reason_en="",
            vendors=unique_valid_names(affected, "vendor"),
            products=unique_valid_names(affected, "product"),
            replacements=replacements,
        )

    rejection_reason = first_english_value(
        cna.get("rejectedReasons"), source=source, field="rejectedReasons"
    )
    if not rejection_reason:
        raise ValidationError(f"{source}: REJECTED CVE has no valid English reason")

    return NormalizedCve(
        cve_id=cve_id,
        state=state,
        description_en="",
        title="",
        rejection_reason_en=rejection_reason,
        vendors=(),
        products=(),
        replacements=replacements,
    )


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as source_file:
            return json.load(source_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"Could not read {path}: {error}") from error


def cve_sort_key(cve_id: str) -> tuple[int, int, str]:
    match = CVE_ID_PATTERN.fullmatch(cve_id)
    if match is None:
        raise ValidationError(f"Invalid CVE ID while sorting: {cve_id!r}")
    return int(match.group(1)), int(match.group(2)), cve_id


def collect_records(source_dir: Path, workers: int) -> list[NormalizedCve]:
    json_paths = sorted(
        source_dir.rglob("*.json"),
        key=lambda path: path.relative_to(source_dir).as_posix(),
    )
    if len(json_paths) != EXPECTED_TOTAL:
        raise ValidationError(
            f"Expected {EXPECTED_TOTAL} JSON files, found {len(json_paths)} in {source_dir}"
        )

    records: list[NormalizedCve] = []
    seen_ids: set[str] = set()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        payloads = executor.map(load_json, json_paths)
        for path, payload in zip(json_paths, payloads):
            record = normalize_record(payload, path)
            if record.cve_id in seen_ids:
                raise ValidationError(f"Duplicate CVE ID: {record.cve_id}")
            seen_ids.add(record.cve_id)
            records.append(record)

    records.sort(key=lambda record: cve_sort_key(record.cve_id))
    return records


def relation_rows(
    records: Iterable[NormalizedCve], attribute: str
) -> list[tuple[str, str]]:
    rows = [
        (record.cve_id, value)
        for record in records
        for value in getattr(record, attribute)
    ]
    rows.sort(key=lambda row: (cve_sort_key(row[0]), row[1].casefold(), row[1]))
    return rows


def validate_model(
    records: Sequence[NormalizedCve],
    vendors: Sequence[tuple[str, str]],
    products: Sequence[tuple[str, str]],
    replacements: Sequence[tuple[str, str]],
) -> None:
    if len(records) != EXPECTED_TOTAL:
        raise ValidationError(
            f"Expected {EXPECTED_TOTAL} normalized CVEs, found {len(records)}"
        )

    ids = [record.cve_id for record in records]
    if len(ids) != len(set(ids)):
        raise ValidationError("Normalized CVE IDs are not unique")

    state_counts = Counter(record.state for record in records)
    if dict(state_counts) != EXPECTED_STATE_COUNTS:
        raise ValidationError(
            f"Unexpected state counts: {dict(state_counts)}; "
            f"expected {EXPECTED_STATE_COUNTS}"
        )

    rejected_without_reason = [
        record.cve_id
        for record in records
        if record.state == "REJECTED" and not record.rejection_reason_en
    ]
    if rejected_without_reason:
        raise ValidationError(
            f"REJECTED CVEs without a reason: {rejected_without_reason[:5]}"
        )

    actual_relations = {
        "vendors": len(vendors),
        "products": len(products),
        "replacements": len(replacements),
    }
    if actual_relations != EXPECTED_RELATION_COUNTS:
        raise ValidationError(
            f"Unexpected relation counts: {actual_relations}; "
            f"expected {EXPECTED_RELATION_COUNTS}"
        )


def write_csv(path: Path, fields: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(fields)
        writer.writerows(rows)


def assert_header(reader: csv.DictReader, expected: Sequence[str], path: Path) -> None:
    if reader.fieldnames != list(expected):
        raise ValidationError(
            f"{path}: header {reader.fieldnames!r} does not match {list(expected)!r}"
        )


def validate_generated_csvs(output_dir: Path) -> dict[str, int]:
    """Reopen the generated files and validate their serialized content."""

    cve_path = output_dir / "cves.csv"
    states: dict[str, str] = {}
    state_counts: Counter[str] = Counter()

    with cve_path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        assert_header(reader, CVES_FIELDS, cve_path)
        for row in reader:
            if any("\r" in value or "\n" in value for value in row.values()):
                raise ValidationError(f"{cve_path}: cell contains a physical line break")

            cve_id = row["cve_id"]
            if cve_id in states:
                raise ValidationError(f"{cve_path}: duplicate CVE ID {cve_id}")
            state = row["state"]
            states[cve_id] = state
            state_counts[state] += 1

            if state == "PUBLISHED":
                if not row["description_en"]:
                    raise ValidationError(
                        f"{cve_path}: PUBLISHED {cve_id} has no description"
                    )
                if row["rejection_reason_en"]:
                    raise ValidationError(
                        f"{cve_path}: PUBLISHED {cve_id} has a rejection reason"
                    )
            elif state == "REJECTED":
                if row["description_en"] or row["title"]:
                    raise ValidationError(
                        f"{cve_path}: REJECTED {cve_id} has published-only fields"
                    )
                if not row["rejection_reason_en"]:
                    raise ValidationError(
                        f"{cve_path}: REJECTED {cve_id} has no reason"
                    )
            else:
                raise ValidationError(f"{cve_path}: unsupported state {state!r}")

    if len(states) != EXPECTED_TOTAL or dict(state_counts) != EXPECTED_STATE_COUNTS:
        raise ValidationError(
            f"{cve_path}: unexpected totals ({len(states)}, {dict(state_counts)})"
        )

    relation_specs = (
        ("vendors", VENDOR_FIELDS, "vendor", True),
        ("products", PRODUCT_FIELDS, "product", True),
        ("replacements", REPLACEMENT_FIELDS, "replaced_by", False),
    )
    relation_counts: dict[str, int] = {}

    for name, fields, value_field, published_only in relation_specs:
        path = output_dir / f"{name}.csv"
        seen_pairs: set[tuple[str, str]] = set()
        count = 0
        with path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            assert_header(reader, fields, path)
            for row in reader:
                if any("\r" in value or "\n" in value for value in row.values()):
                    raise ValidationError(f"{path}: cell contains a physical line break")

                cve_id = row["cve_id"]
                value = row[value_field]
                if cve_id not in states:
                    raise ValidationError(f"{path}: unknown source CVE ID {cve_id}")
                if published_only and states[cve_id] != "PUBLISHED":
                    raise ValidationError(
                        f"{path}: relation for non-PUBLISHED CVE {cve_id}"
                    )
                if not value:
                    raise ValidationError(f"{path}: empty {value_field} for {cve_id}")
                if published_only and value.casefold() in PLACEHOLDERS:
                    raise ValidationError(
                        f"{path}: placeholder {value!r} for {cve_id}"
                    )
                if name == "replacements" and not CVE_ID_PATTERN.fullmatch(value):
                    raise ValidationError(
                        f"{path}: invalid replacement CVE ID {value!r}"
                    )

                pair = cve_id, value.casefold()
                if pair in seen_pairs:
                    raise ValidationError(f"{path}: duplicate relation {pair}")
                seen_pairs.add(pair)
                count += 1

        relation_counts[name] = count

    if relation_counts != EXPECTED_RELATION_COUNTS:
        raise ValidationError(
            f"Generated relation counts are {relation_counts}; "
            f"expected {EXPECTED_RELATION_COUNTS}"
        )

    return {
        "total": len(states),
        "published": state_counts["PUBLISHED"],
        "rejected": state_counts["REJECTED"],
        **relation_counts,
    }


def generate(source_dir: Path, output_dir: Path, workers: int) -> dict[str, int]:
    records = collect_records(source_dir, workers)
    vendors = relation_rows(records, "vendors")
    products = relation_rows(records, "products")
    replacements = relation_rows(records, "replacements")
    validate_model(records, vendors, products, replacements)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix=f".{output_dir.name}-", dir=output_dir.parent
    ) as temporary_name:
        temporary_dir = Path(temporary_name)
        write_csv(
            temporary_dir / "cves.csv",
            CVES_FIELDS,
            (
                (
                    record.cve_id,
                    record.state,
                    encode_single_line_text(record.description_en),
                    encode_single_line_text(record.title),
                    encode_single_line_text(record.rejection_reason_en),
                )
                for record in records
            ),
        )
        write_csv(
            temporary_dir / "vendors.csv",
            VENDOR_FIELDS,
            ((cve_id, encode_single_line_text(value)) for cve_id, value in vendors),
        )
        write_csv(
            temporary_dir / "products.csv",
            PRODUCT_FIELDS,
            ((cve_id, encode_single_line_text(value)) for cve_id, value in products),
        )
        write_csv(
            temporary_dir / "replacements.csv", REPLACEMENT_FIELDS, replacements
        )

        validate_generated_csvs(temporary_dir)
        for filename in (
            "cves.csv",
            "vendors.csv",
            "products.csv",
            "replacements.csv",
        ):
            os.replace(temporary_dir / filename, output_dir / filename)

    return validate_generated_csvs(output_dir)


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Generate the normalized 2025 CVE Finder CSV dataset."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=project_root.parent / "cvelistV5" / "cves" / "2025",
        help="Directory containing the official 2025 CVE JSON files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "data",
        help="Directory where the four normalized CSV files will be written.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(12, (os.cpu_count() or 1) + 4),
        help="Number of worker threads used to read JSON files.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source_dir = args.source.resolve()
    output_dir = args.output.resolve()
    if not source_dir.is_dir():
        raise SystemExit(f"Source directory does not exist: {source_dir}")
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")

    try:
        summary = generate(source_dir, output_dir, args.workers)
    except ValidationError as error:
        raise SystemExit(f"Validation failed: {error}") from error

    print(f"Source: {source_dir}")
    print(f"Output: {output_dir}")
    print(f"CVEs: {summary['total']}")
    print(f"PUBLISHED: {summary['published']}")
    print(f"REJECTED: {summary['rejected']}")
    print(f"Vendor relations: {summary['vendors']}")
    print(f"Product relations: {summary['products']}")
    print(f"Replacement relations: {summary['replacements']}")
    print("Validation: OK")


if __name__ == "__main__":
    main()
