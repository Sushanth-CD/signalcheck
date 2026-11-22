"""Read-only, streaming audit of the three local source datasets.

Uses only the Python standard library. Run from any working directory with:
    python backend/notebooks/audit_datasets.py

The Android workbook is read directly from the already extracted copy under
backend/data/raw/android_extracted; no files are written or extracted.
"""

from __future__ import annotations

import csv
import hashlib
import json
import posixpath
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "backend" / "data" / "raw"
PHISHING_PATH = RAW / "combined_reduced.json"
HINGLISH_PATH = RAW / "indian_cyber_scam_hinglish.csv"
ANDROID_BOOK = RAW / "android_extracted" / "Android Benign and Malware Dataset2" / "AndroidDataset.xlsx"
HTML_RE = re.compile(r"<\s*(?:!doctype\s+html|html|head|body|div|p|table|a|script|meta|title)\b", re.I)
URL_RE = re.compile(
    r"(?:https?://|www\.)\S+|\b[a-z0-9.-]+\.(?:com|net|org|info|biz|co|io|edu|gov|uk|in)\b",
    re.I,
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
XML_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
XML_REL_DOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XML_REL_PKG = "http://schemas.openxmlformats.org/package/2006/relationships"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def iter_json_array_objects(path: Path) -> Iterator[dict[str, Any]]:
    """Decode objects from a JSON array without reading the full file at once."""
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as stream:
        buffer = ""
        pos = 0
        eof = False
        while True:
            while pos < len(buffer) and (buffer[pos].isspace() or buffer[pos] in "[],"):
                pos += 1
            if pos >= len(buffer):
                if eof:
                    return
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    eof = True
                    if pos >= len(buffer):
                        return
                buffer = buffer[pos:] + chunk
                pos = 0
                continue
            try:
                value, end = decoder.raw_decode(buffer, pos)
            except json.JSONDecodeError:
                if eof:
                    raise
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    eof = True
                else:
                    buffer = buffer[pos:] + chunk
                    pos = 0
                continue
            if not isinstance(value, dict):
                raise ValueError("Expected each top-level JSON array item to be an object")
            yield value
            pos = end
            if pos > 2 * 1024 * 1024:
                buffer = buffer[pos:]
                pos = 0


def content_kind(text: str) -> str:
    # Mutually exclusive priority gives a reproducible, approximate summary.
    if HTML_RE.search(text):
        return "HTML"
    if URL_RE.search(text):
        return "URL-like"
    if EMAIL_RE.search(text):
        return "email-like"
    return "other text"


def audit_phishing() -> dict[str, Any]:
    rows = 0
    labels: Counter[str] = Counter()
    text_status: Counter[str] = Counter()
    types: Counter[str] = Counter()
    types_by_label: dict[str, Counter[str]] = defaultdict(Counter)
    text_hashes: dict[str, set[str]] = {}
    examples: dict[str, dict[str, str]] = defaultdict(dict)
    for record in iter_json_array_objects(PHISHING_PATH):
        rows += 1
        label = str(record.get("label", "<missing>"))
        labels[label] += 1
        if "text" not in record:
            text_status["missing"] += 1
            continue
        text = record["text"] if isinstance(record["text"], str) else ""
        if not text.strip():
            text_status["empty"] += 1
        kind = content_kind(text) if text.strip() else "empty"
        if kind != "empty":
            types[kind] += 1
            types_by_label[label][kind] += 1
            examples[label].setdefault(kind, re.sub(r"\s+", " ", text)[:330])
        digest = sha(text)
        text_hashes.setdefault(digest, set()).add(label)
    unique_texts = len(text_hashes)
    conflicts = sum(len(label_set) > 1 for label_set in text_hashes.values())
    return {
        "records": rows,
        "label_counts": dict(labels),
        "label_percentages": {k: round(v * 100 / rows, 2) for k, v in labels.items()} if rows else {},
        "missing_or_empty_text": dict(text_status),
        "unique_text_values_sha256_including_empty": unique_texts,
        "duplicate_rows_beyond_first": rows - unique_texts,
        "unique_texts_with_conflicting_labels": conflicts,
        "exclusive_approximate_content_types": dict(types),
        "types_by_label": {k: dict(v) for k, v in types_by_label.items()},
        "representative_examples_by_label_and_type": dict(examples),
        "content_type_method": "HTML, then URL-like, then email-like, else other; approximate and exclusive.",
    }


def normalize_message(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def audit_hinglish() -> dict[str, Any]:
    rows = 0
    missing: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    exact: dict[str, dict[str, Any]] = {}
    normalized: dict[str, dict[str, Any]] = {}
    examples: dict[str, str] = {}
    with HINGLISH_PATH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        schema = reader.fieldnames or []
        for record in reader:
            rows += 1
            label = record.get("label", "")
            category = record.get("scam_category", "")
            text = record.get("text", "") or ""
            labels[label] += 1
            categories[category] += 1
            for field in schema:
                if not (record.get(field) or "").strip():
                    missing[field] += 1
            exact_key = sha(text)
            norm_key = sha(normalize_message(text))
            exact.setdefault(exact_key, {"labels": set()})["labels"].add(label)
            group = normalized.setdefault(
                norm_key,
                {"count": 0, "labels": set(), "categories": set(), "sample": text},
            )
            group["count"] += 1
            group["labels"].add(label)
            group["categories"].add(category)
            examples.setdefault(category, text)
    dedup_category_pairs = Counter()
    for group in normalized.values():
        for category in group["categories"]:
            dedup_category_pairs[category] += 1
    return {
        "records": rows,
        "schema": schema,
        "missing_or_empty_by_column": dict(missing),
        "label_counts": dict(labels),
        "category_counts_before_deduplication": dict(categories),
        "unique_exact_texts": len(exact),
        "unique_normalized_texts": len(normalized),
        "normalized_messages_repeated_more_than_once": sum(g["count"] > 1 for g in normalized.values()),
        "duplicate_rows_beyond_first_normalized_message": rows - len(normalized),
        "messages_with_conflicting_labels": sum(len(g["labels"]) > 1 for g in normalized.values()),
        "messages_with_conflicting_categories": sum(len(g["categories"]) > 1 for g in normalized.values()),
        "deduplicated_text_category_associations_nonexclusive": dict(dedup_category_pairs),
        "representative_row_example_by_category": examples,
        "unique_text_counts_for_categories": {
            category: sum(category in group["categories"] for group in normalized.values())
            for category in categories
        },
        "unique_texts_with_category_conflicts": [
            {"sample": group["sample"], "categories": sorted(group["categories"])}
            for group in normalized.values()
            if len(group["categories"]) > 1
        ][:10],
    }


def col_index(cell_ref: str) -> int:
    value = 0
    for char in re.match(r"[A-Z]+", cell_ref).group(0):
        value = value * 26 + ord(char) - 64
    return value - 1


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def audit_android() -> dict[str, Any]:
    if not ANDROID_BOOK.exists():
        return {"available": False, "limitation": f"Workbook not found at {ANDROID_BOOK}"}
    with zipfile.ZipFile(ANDROID_BOOK, "r") as book:
        workbook = ET.fromstring(book.read("xl/workbook.xml"))
        rels = ET.fromstring(book.read("xl/_rels/workbook.xml.rels"))
        relationship_targets = {
            rel.attrib["Id"]: rel.attrib["Target"]
            for rel in rels.findall(f"{{{XML_REL_PKG}}}Relationship")
        }
        sheet_info = []
        for sheet in workbook.findall(f"{{{XML_MAIN}}}sheets/{{{XML_MAIN}}}sheet"):
            target = relationship_targets[sheet.attrib[f"{{{XML_REL_DOC}}}id"]]
            sheet_path = posixpath.normpath(posixpath.join("xl", target))
            sheet_info.append({"name": sheet.attrib["name"], "path": sheet_path})
        shared_strings: list[str] = []
        with book.open("xl/sharedStrings.xml") as shared_stream:
            for _, element in ET.iterparse(shared_stream, events=("end",)):
                if local_name(element.tag) == "si":
                    shared_strings.append("".join(element.itertext()))
                    element.clear()
        if not sheet_info:
            return {"available": False, "limitation": "Workbook has no worksheets"}
        sheet_path = sheet_info[0]["path"]
        label_counts: Counter[str] = Counter()
        package_rows: dict[str, dict[str, Any]] = {}
        exact_rows: set[str] = set()
        feature_rows: dict[str, set[str]] = {}
        blank_cells = 0
        total_cells = 0
        missing_output = 0
        samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
        headers: list[str] = []
        header_map: dict[str, int] = {}
        dimension = None
        data_rows = 0
        with book.open(sheet_path) as sheet_stream:
            for event, element in ET.iterparse(sheet_stream, events=("start", "end")):
                name = local_name(element.tag)
                if event == "start" and name == "dimension":
                    dimension = element.attrib.get("ref")
                if event != "end" or name != "row":
                    continue
                cells: dict[int, str] = {}
                cell_count = 0
                for cell in element:
                    if local_name(cell.tag) != "c":
                        continue
                    cell_count += 1
                    ref = cell.attrib.get("r", "")
                    index = col_index(ref)
                    value_element = next((child for child in cell if local_name(child.tag) == "v"), None)
                    value = value_element.text if value_element is not None and value_element.text is not None else ""
                    if cell.attrib.get("t") == "s" and value:
                        value = shared_strings[int(value)]
                    elif cell.attrib.get("t") == "inlineStr":
                        value = "".join(cell.itertext())
                    if not value:
                        blank_cells += 1
                    cells[index] = value
                total_cells += cell_count
                row_no = int(element.attrib.get("r", "0"))
                if row_no == 1:
                    last_col = max(cells, default=-1)
                    headers = [cells.get(i, "") for i in range(last_col + 1)]
                    header_map = {name: i for i, name in enumerate(headers)}
                else:
                    data_rows += 1
                    values = [cells.get(i, "") for i in range(len(headers))]
                    output_index = header_map.get("OUTPUT")
                    label = values[output_index] if output_index is not None else ""
                    if not label:
                        missing_output += 1
                    else:
                        label_counts[label] += 1
                    package = values[header_map.get("Package", 0)] if headers else ""
                    category = values[header_map.get("Category", 1)] if len(headers) > 1 else ""
                    pkg = package_rows.setdefault(package, {"rows": 0, "labels": set()})
                    pkg["rows"] += 1
                    pkg["labels"].add(label)
                    full_digest = sha(json.dumps(values, ensure_ascii=False, separators=(",", ":")))
                    exact_rows.add(full_digest)
                    features = values[:output_index] + values[output_index + 1 :] if output_index is not None else values
                    feature_digest = sha(json.dumps(features, ensure_ascii=False, separators=(",", ":")))
                    feature_rows.setdefault(feature_digest, set()).add(label)
                    if label and len(samples[label]) < 3:
                        samples[label].append({"package": package, "category": category,
                                               "nonzero_features": sum(v.casefold() in {"1", "true"} for v in features[2:])})
                element.clear()
        duplicate_packages = [p for p in package_rows.values() if p["rows"] > 1]
        return {
            "available": True,
            "worksheets": [{"name": sheet["name"], "dimension": dimension} for sheet in sheet_info],
            "data_rows": data_rows,
            "column_count": len(headers),
            "headers_first_15": headers[:15],
            "headers_last_15": headers[-15:],
            "likely_target_column": "OUTPUT" if "OUTPUT" in headers else None,
            "output_distribution": dict(label_counts),
            "rows_missing_output": missing_output,
            "feature_cell_blank_count": blank_cells,
            "stored_cells_count": total_cells,
            "unique_exact_records_by_normalized_values": len(exact_rows),
            "duplicate_exact_record_rows_beyond_first": data_rows - len(exact_rows),
            "duplicate_feature_records_beyond_first_ignoring_output": data_rows - len(feature_rows),
            "unique_package_ids": len(package_rows),
            "duplicate_package_ids": len(duplicate_packages),
            "duplicate_rows_by_package_id": sum(p["rows"] - 1 for p in duplicate_packages),
            "package_ids_with_conflicting_output_values": sum(len(p["labels"]) > 1 for p in package_rows.values()),
            "representative_rows_by_output_value": dict(samples),
            "shared_string_count": len(shared_strings),
        }


def main() -> int:
    reports: dict[str, Any] = {}
    for name, function in (
        ("phishing", audit_phishing),
        ("hinglish", audit_hinglish),
        ("android", audit_android),
    ):
        try:
            print(f"Auditing {name}...", file=sys.stderr, flush=True)
            reports[name] = function()
        except Exception as error:  # Preserve completed audit results on a local data error.
            reports[name] = {"error": f"{type(error).__name__}: {error}"}
    print(json.dumps(reports, ensure_ascii=False, indent=2, default=list))
    return 0 if not any("error" in item for item in reports.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
