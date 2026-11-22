"""Prepare read-only-derived text and Android candidates; never trains models.

Run from the repository root with:
    python backend/notebooks/prepare_ml_datasets.py

Only the named output files under backend/data/processed are replaced when
rerun. Temporary outputs are staged there and atomically moved into place on
success. Raw datasets are opened read-only. Uses Python standard library only.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import posixpath
import re
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "backend" / "data" / "raw"
OUT = ROOT / "backend" / "data" / "processed"
PHISHING = RAW / "combined_reduced.json"
HINGLISH = RAW / "indian_cyber_scam_hinglish.csv"
ANDROID_BOOK = RAW / "android_extracted" / "Android Benign and Malware Dataset2" / "AndroidDataset.xlsx"
ANDROID_SOURCE = "android_benign_malware_dataset2"
ANDROID_OUTPUT_POLARITY_VERIFIED = False

OUTPUT_NAMES = (
    "phishing_text_candidates.jsonl",
    "hinglish_text_candidates.jsonl",
    "android_permission_candidates.csv",
    "android_package_label_conflicts.csv",
    "digital_arrest_coverage.md",
    "android_feature_audit.json",
    "preparation_summary.json",
    "dataset_preparation_report.md",
)

HTML_RE = re.compile(r"<\s*(?:!doctype\s+html|html|head|body|form|input|table|div|script|meta|title)\b", re.I)
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9.-]+\.[a-z]{2,63}(?:/[^\s<>\"']*)?", re.I)
URL_ONLY_RE = re.compile(
    r"\s*(?:(?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9-]+\.)+[a-z]{2,63}(?:/[^\s<>\"']*)?)(?:\s+|[,;]\s*)*\s*",
    re.I,
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
EMAIL_HEADER_RE = re.compile(r"(?im)^(?:from|to|cc|bcc|subject|date|mime-version|content-type|message-id):\s*\S")
EMAIL_FOOTER_RE = re.compile(r"(?i)\b(?:unsubscribe|manage your (?:email )?preferences|email newsletter|newsletter)\b")
PROMO_RE = re.compile(
    r"(?i)\b(?:text\s+[a-z0-9]+\s+to\s+\d{4,}|unsubscribe|manage your (?:email )?preferences|"
    r"free (?:ringtones?|trial|gift|prize)|sex up your mobile|limited[- ]time offer)\b"
)
XML_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
XML_REL_DOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XML_REL_PKG = "http://schemas.openxmlformats.org/package/2006/relationships"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def jsonl_record(value: Any) -> str:
    """Serialize one JSONL record; escape Unicode line separators for tooling."""
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def input_type(text: str) -> tuple[str, list[str]]:
    """Return a transparent primary type plus independent content signals.

    HTML has priority over email, then a URL-only field, then plain text.
    Embedded URL/address signals are retained separately. Plain text is not
    called SMS because the source field does not identify the original channel.
    """
    signals: list[str] = []
    if HTML_RE.search(text):
        signals.append("html_markup")
    if URL_RE.search(text):
        signals.append("url_like_string")
    if EMAIL_RE.search(text):
        signals.append("email_address")
    if EMAIL_HEADER_RE.search(text):
        signals.append("email_header")
    if EMAIL_FOOTER_RE.search(text):
        signals.append("email_or_newsletter_footer")
    if "html_markup" in signals:
        return "html", signals
    if "email_header" in signals or "email_or_newsletter_footer" in signals:
        return "email", signals
    if URL_ONLY_RE.fullmatch(text):
        return "url", signals
    return "plain_text", signals


def iter_json_array(path: Path) -> Iterator[dict[str, Any]]:
    """Incrementally decode a top-level JSON array of objects."""
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as stream:
        buffer, position, eof = "", 0, False
        while True:
            while position < len(buffer) and (buffer[position].isspace() or buffer[position] in "[],"):
                position += 1
            if position >= len(buffer):
                if eof:
                    return
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    eof = True
                    if position >= len(buffer):
                        return
                buffer = buffer[position:] + chunk
                position = 0
                continue
            try:
                record, end = decoder.raw_decode(buffer, position)
            except json.JSONDecodeError:
                if eof:
                    raise
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    eof = True
                else:
                    buffer = buffer[position:] + chunk
                    position = 0
                continue
            if not isinstance(record, dict):
                raise ValueError("The phishing JSON array contains a non-object record")
            yield record
            position = end
            if position > 2 * 1024 * 1024:
                buffer = buffer[position:]
                position = 0


def load_hinglish_groups() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    row_count = 0
    with HINGLISH.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        for row_index, row in enumerate(reader, start=2):
            row_count += 1
            text = row.get("text", "") or ""
            key = digest(normalize(text))
            group = groups.setdefault(
                key,
                {
                    "text": text,
                    "normalized": normalize(text),
                    "labels": set(),
                    "categories": set(),
                    "source_row_indices": [],
                    "source_row_count": 0,
                },
            )
            group["labels"].add(str(row.get("label", "")))
            group["categories"].add(str(row.get("scam_category", "")))
            group["source_row_indices"].append(row_index)
            group["source_row_count"] += 1
    stats = {
        "source_rows": row_count,
        "unique_normalized_messages": len(groups),
        "duplicates_beyond_first": row_count - len(groups),
        "repeated_message_groups": sum(group["source_row_count"] > 1 for group in groups.values()),
        "messages_with_conflicting_labels": sum(len(group["labels"]) > 1 for group in groups.values()),
        "messages_with_conflicting_categories": sum(len(group["categories"]) > 1 for group in groups.values()),
    }
    return groups, stats


def prepare_phishing(path: Path, hinglish_norms: set[str]) -> dict[str, Any]:
    duplicate_groups: dict[str, dict[str, Any]] = {}
    source_rows = 0
    empty_rows = 0
    # Pass one builds only compact hashes/counts, not a second copy of raw text.
    for record in iter_json_array(PHISHING):
        source_rows += 1
        text = record.get("text")
        if not isinstance(text, str) or not text.strip():
            empty_rows += 1
            continue
        key = digest(text)
        group = duplicate_groups.setdefault(key, {"count": 0, "labels": set()})
        group["count"] += 1
        group["labels"].add(str(record.get("label", "")))
    input_types: Counter[str] = Counter()
    review_count = 0
    type_overlap_count = 0
    cross_source_overlap_hashes: set[str] = set()
    written = 0
    with path.open("w", encoding="utf-8", newline="\n") as output:
        for source_index, record in enumerate(iter_json_array(PHISHING), start=1):
            text = record.get("text")
            if not isinstance(text, str) or not text.strip():
                continue
            label = str(record.get("label", ""))
            kind, signals = input_type(text)
            input_types[kind] += 1
            type_overlap_count += len(signals) > 1
            normalized_text = normalize(text)
            if normalized_text in hinglish_norms:
                cross_source_overlap_hashes.add(digest(normalized_text))
            key = digest(text)
            reasons: list[str] = []
            if label == "1" and PROMO_RE.search(text):
                reasons.append("possible_promotional_or_non_phishing_spam_review")
            if len(duplicate_groups[key]["labels"]) > 1:
                reasons.append("exact_duplicate_has_conflicting_source_labels")
            row = {
                "text": text,
                "label_original": label,
                "source_dataset": "combined_reduced.json",
                "inferred_input_type": kind,
                "review_required": bool(reasons),
                "review_reason": reasons,
                "source_record_index": source_index,
                "duplicate_group_sha256": key,
                "duplicate_count": duplicate_groups[key]["count"],
                "duplicate_label_conflict": len(duplicate_groups[key]["labels"]) > 1,
                "content_signals": signals,
            }
            output.write(jsonl_record(row) + "\n")
            written += 1
            review_count += bool(reasons)
    return {
        "source_rows": source_rows,
        "candidate_rows_excluding_empty_text": written,
        "empty_text_rows_excluded": empty_rows,
        "unique_nonempty_exact_texts": len(duplicate_groups),
        "duplicate_rows_beyond_first": written - len(duplicate_groups),
        "duplicate_text_groups_with_conflicting_labels": sum(
            len(group["labels"]) > 1 for group in duplicate_groups.values()
        ),
        "inferred_input_type_counts": dict(input_types),
        "rows_with_multiple_content_signals": type_overlap_count,
        "possible_promotional_spam_rows_flagged_for_review": review_count,
        "exact_normalized_text_overlap_with_hinglish_unique_texts": len(cross_source_overlap_hashes),
        "input_type_rules": {
            "html": "recognized HTML structural tags or doctype; wins primary-type precedence",
            "email": "explicit email headers or recognizable unsubscribe/newsletter footer",
            "url": "text consists only of URL/domain-like tokens",
            "plain_text": "all remaining nonempty text; does not imply SMS channel",
            "content_signals": "HTML marker, URL-like string, email address, or email/newsletter header/footer may coexist",
            "review": "label 1 plus explicit promotional/paid-SMS/newsletter cues is flagged for human review, never relabeled",
        },
    }


def prepare_hinglish(path: Path, groups: dict[str, dict[str, Any]]) -> dict[str, Any]:
    input_types: Counter[str] = Counter()
    with path.open("w", encoding="utf-8", newline="\n") as output:
        for group in groups.values():
            kind, signals = input_type(group["text"])
            input_types[kind] += 1
            label_conflict = len(group["labels"]) > 1
            category_conflict = len(group["categories"]) > 1
            reasons = []
            if label_conflict:
                reasons.append("normalized_duplicate_has_conflicting_source_labels")
            if category_conflict:
                reasons.append("conflicting_source_scam_category_metadata")
            row = {
                "text": group["text"],
                "label_original": sorted(group["labels"])[0] if len(group["labels"]) == 1 else None,
                "source_dataset": "indian_cyber_scam_hinglish.csv",
                "inferred_input_type": kind,
                "review_required": bool(reasons),
                "review_reason": reasons,
                "content_signals": signals,
                "normalized_text_sha256": digest(group["normalized"]),
                "source_row_count": group["source_row_count"],
                "source_row_indices": group["source_row_indices"],
                "source_categories": sorted(group["categories"]),
                "category_conflict": category_conflict,
                "label_conflict": label_conflict,
            }
            output.write(jsonl_record(row) + "\n")
    return {
        "candidate_rows_one_per_normalized_message": len(groups),
        "source_rows": sum(group["source_row_count"] for group in groups.values()),
        "duplicate_rows_beyond_first": sum(group["source_row_count"] - 1 for group in groups.values()),
        "messages_with_conflicting_labels": sum(len(group["labels"]) > 1 for group in groups.values()),
        "messages_with_conflicting_categories": sum(len(group["categories"]) > 1 for group in groups.values()),
        "inferred_input_type_counts": dict(input_types),
        "metadata_model_inputs": [],
    }


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _column_index(reference: str) -> int:
    match = re.match(r"[A-Z]+", reference)
    number = 0
    for char in match.group(0):
        number = number * 26 + ord(char) - 64
    return number - 1


def audit_and_prepare_android(candidate_path: Path, conflicts_path: Path) -> dict[str, Any]:
    if not ANDROID_BOOK.exists():
        raise FileNotFoundError(f"Expected extracted read-only workbook not found: {ANDROID_BOOK}")
    counts: Counter[str] = Counter()
    package_rows: dict[str, dict[str, Any]] = {}
    exact_record_hashes: set[str] = set()
    feature_record_hashes: set[str] = set()
    blank_cells = 0
    stored_data_cells = 0
    sample_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    dimension = None
    worksheet_name = None
    candidate_file = candidate_path.open("w", encoding="utf-8", newline="")
    candidate_writer = csv.writer(candidate_file)
    with zipfile.ZipFile(ANDROID_BOOK, "r") as book:
        workbook = ET.fromstring(book.read("xl/workbook.xml"))
        relationships = ET.fromstring(book.read("xl/_rels/workbook.xml.rels"))
        targets = {
            rel.attrib["Id"]: rel.attrib["Target"]
            for rel in relationships.findall(f"{{{XML_REL_PKG}}}Relationship")
        }
        sheet = workbook.find(f"{{{XML_MAIN}}}sheets/{{{XML_MAIN}}}sheet")
        if sheet is None:
            raise ValueError("Workbook has no worksheet")
        worksheet_name = sheet.attrib["name"]
        sheet_path = posixpath.normpath(
            posixpath.join("xl", targets[sheet.attrib[f"{{{XML_REL_DOC}}}id"]])
        )
        shared_strings: list[str] = []
        with book.open("xl/sharedStrings.xml") as stream:
            for _, element in ET.iterparse(stream, events=("end",)):
                if _local(element.tag) == "si":
                    shared_strings.append("".join(element.itertext()))
                    element.clear()
        header_names: list[str] = []
        header_positions: dict[str, int] = {}
        feature_positions: list[int] = []
        ones: list[int] = []
        zeros: list[int] = []
        nulls: list[int] = []
        nonbinary: list[int] = []
        bitsets: list[bytearray] = []
        data_row_count = 0
        with book.open(sheet_path) as stream:
            for event, element in ET.iterparse(stream, events=("start", "end")):
                name = _local(element.tag)
                if event == "start" and name == "dimension":
                    dimension = element.attrib.get("ref")
                if event != "end" or name != "row":
                    continue
                row_values: dict[int, str] = {}
                for cell in element:
                    if _local(cell.tag) != "c":
                        continue
                    col = _column_index(cell.attrib.get("r", ""))
                    value_node = next((child for child in cell if _local(child.tag) == "v"), None)
                    value = value_node.text if value_node is not None and value_node.text else ""
                    if cell.attrib.get("t") == "s" and value:
                        value = shared_strings[int(value)]
                    elif cell.attrib.get("t") == "inlineStr":
                        value = "".join(cell.itertext())
                    row_values[col] = value
                row_number = int(element.attrib.get("r", "0"))
                if row_number == 1:
                    header_names = [row_values.get(i, "") for i in range(max(row_values) + 1)]
                    header_positions = {header: index for index, header in enumerate(header_names)}
                    if "OUTPUT" not in header_positions:
                        raise ValueError("Could not find OUTPUT target column")
                    feature_positions = [
                        i for i, header in enumerate(header_names)
                        if header not in {"Package", "Category", "OUTPUT"}
                    ]
                    bit_size = (121190 + 7) // 8
                    bitsets = [bytearray(bit_size) for _ in feature_positions]
                    ones = [0] * len(feature_positions)
                    zeros = [0] * len(feature_positions)
                    nulls = [0] * len(feature_positions)
                    nonbinary = [0] * len(feature_positions)
                    candidate_writer.writerow([
                        "source_row_index", "label_original", "source_dataset", "review_required", "review_reason",
                        *[header_names[i] for i in feature_positions],
                    ])
                else:
                    data_row_count += 1
                    stored_data_cells += len(row_values)
                    blank_cells += sum(not value for value in row_values.values())
                    values = [row_values.get(i, "") for i in range(len(header_names))]
                    label = values[header_positions["OUTPUT"]]
                    counts[label] += 1
                    package = values[header_positions["Package"]]
                    category = values[header_positions["Category"]]
                    package_group = package_rows.setdefault(package, {"rows": [], "outputs": set(), "categories": set()})
                    package_group["rows"].append(row_number)
                    package_group["outputs"].add(label)
                    package_group["categories"].add(category)
                    exact_record_hashes.add(digest(json.dumps(values, ensure_ascii=False, separators=(",", ":"))))
                    feature_values = [values[i] for i in feature_positions]
                    feature_record_hashes.add(digest(json.dumps(feature_values, ensure_ascii=False, separators=(",", ":"))))
                    for j, value in enumerate(feature_values):
                        if value == "1":
                            ones[j] += 1
                            bitsets[j][(data_row_count - 1) >> 3] |= 1 << ((data_row_count - 1) & 7)
                        elif value == "0":
                            zeros[j] += 1
                        elif not value:
                            nulls[j] += 1
                        else:
                            nonbinary[j] += 1
                    # source_row_index is audit metadata; Package and Category are deliberately omitted.
                    candidate_writer.writerow([
                        row_number, label, ANDROID_SOURCE, "true",
                        "output_polarity_not_verified_from_dataset_documentation",
                        *feature_values,
                    ])
                    if len(sample_rows[label]) < 3:
                        sample_rows[label].append({"source_row_index": row_number, "package": package,
                                                   "category": category, "nonzero_features": sum(v == "1" for v in feature_values)})
                element.clear()
        candidate_file.flush()
        candidate_file.close()

    # Build an exact lookup of constant and duplicate binary feature vectors.
    vector_groups: dict[bytes, list[int]] = defaultdict(list)
    constant_features: list[str] = []
    all_null_features: list[str] = []
    nonbinary_features: list[str] = []
    for j, original_column in enumerate(feature_positions):
        name = header_names[original_column]
        if nulls[j] == data_row_count:
            all_null_features.append(name)
        if nonbinary[j]:
            nonbinary_features.append(name)
            continue
        if nulls[j] == 0 and (ones[j] == 0 or zeros[j] == 0):
            constant_features.append(name)
        if nulls[j] == 0:
            vector_groups[bytes(bitsets[j])].append(j)
    duplicate_groups = [indices for indices in vector_groups.values() if len(indices) > 1]
    duplicate_columns = [header_names[feature_positions[i]] for group in duplicate_groups for i in group[1:]]

    conflict_groups = [(package, group) for package, group in package_rows.items() if len(group["outputs"]) > 1]
    with conflicts_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["package_id_not_for_model", "source_row_indices", "output_values", "app_categories", "review_required", "review_reason"])
        for package, group in sorted(conflict_groups):
            writer.writerow([
                package,
                json.dumps(group["rows"]),
                json.dumps(sorted(group["outputs"])),
                json.dumps(sorted(group["categories"]), ensure_ascii=False),
                "true",
                "same_package_identifier_has_multiple_original_OUTPUT_values; determine version/source before inclusion",
            ])

    return {
        "worksheet": worksheet_name,
        "dimension": dimension,
        "data_rows": data_row_count,
        "column_count_including_package_category_output": len(header_names),
        "feature_column_count_excluding_package_category_output": len(feature_positions),
        "feature_columns": [header_names[i] for i in feature_positions],
        "output_distribution": dict(counts),
        "output_semantics_verified": ANDROID_OUTPUT_POLARITY_VERIFIED,
        "all_android_rows_review_required": True,
        "review_reason": "The Mendeley source description available for this file does not define OUTPUT 0/1 polarity.",
        "identifier_columns_excluded_from_features": ["Package", "Category"],
        "audit_metadata_excluded_from_features": ["source_row_index", "label_original", "source_dataset", "review_required", "review_reason"],
        "missing_or_blank_feature_cells": sum(nulls),
        "all_null_feature_columns": all_null_features,
        "constant_feature_column_count": len(constant_features),
        "constant_feature_columns": constant_features,
        "nonbinary_feature_columns_not_in_binary_duplicate_check": nonbinary_features,
        "duplicate_feature_column_groups": [
            [header_names[feature_positions[index]] for index in group]
            for group in duplicate_groups
        ],
        "duplicate_feature_columns_beyond_first": len(duplicate_columns),
        "full_row_duplicates_beyond_first": data_row_count - len(exact_record_hashes),
        "candidate_feature_only_duplicate_rows_beyond_first": data_row_count - len(feature_record_hashes),
        "package_identifier_count": len(package_rows),
        "package_identifiers_repeated": sum(len(group["rows"]) > 1 for group in package_rows.values()),
        "package_rows_beyond_first": sum(len(group["rows"]) - 1 for group in package_rows.values()),
        "package_identifiers_with_conflicting_OUTPUT": len(conflict_groups),
        "package_conflict_file_rows": len(conflict_groups),
        "sample_rows_by_OUTPUT": dict(sample_rows),
        "stored_data_cells": stored_data_cells,
    }


def write_markdown(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    outputs = {name: OUT / name for name in OUTPUT_NAMES}
    # These exact files are owned by this script; unrelated files are untouched.
    staged: dict[str, Path] = {}
    try:
        for name, target in outputs.items():
            with tempfile.NamedTemporaryFile(prefix=f".{target.stem}.", suffix=".tmp", dir=OUT, delete=False) as temp:
                staged[name] = Path(temp.name)

        hinglish_groups, hinglish_stats = load_hinglish_groups()
        hinglish_norms = {group["normalized"] for group in hinglish_groups.values()}
        phishing_stats = prepare_phishing(staged["phishing_text_candidates.jsonl"], hinglish_norms)
        hinglish_candidate_stats = prepare_hinglish(staged["hinglish_text_candidates.jsonl"], hinglish_groups)
        android_stats = audit_and_prepare_android(
            staged["android_permission_candidates.csv"],
            staged["android_package_label_conflicts.csv"],
        )

        da_groups = [g for g in hinglish_groups.values() if "police_digital_arrest" in g["categories"]]
        literal_da = re.compile(r"(?i)\bdigital\s+arrest|\bdigitally\s+arrest|\bdigital\s+custody|\bonline\s+custody|\bvirtual(?:ly)?\s+(?:detained|custody)")
        authority = re.compile(r"(?i)\bpolice\b|\bcbi\b|cyber\s*crime|cybercrime|officer|investigation team|thana|inspector")
        da_literal_count = sum(bool(literal_da.search(g["text"])) for g in da_groups)
        da_authority_count = sum(bool(authority.search(g["text"])) for g in da_groups)
        da_report = [
            "# Hinglish digital-arrest coverage (metadata and text audit)", "",
            f"- Source rows: {hinglish_stats['source_rows']}",
            f"- Unique normalized messages assigned `police_digital_arrest`: {len(da_groups)}",
            f"- Such unique messages containing a literal digital-arrest / digital-custody / online-custody / virtual-detention phrase: {da_literal_count}",
            f"- Such unique messages with explicit police/CBI/cybercrime/authority vocabulary: {da_authority_count}",
            f"- Unique normalized messages with conflicting categories: {hinglish_stats['messages_with_conflicting_categories']}",
            "",
            "These are category metadata counts and simple text-marker counts, not adjudicated scam labels. The literal phrase search is intentionally narrow; absence of those English phrases does not prove absence of a digital-arrest scenario. The categories remain unchanged in the candidate file.",
            "",
            "Examples assigned `police_digital_arrest`:",
        ]
        da_report.extend(f"- {g['text']}" for g in da_groups[:8])
        write_markdown(staged["digital_arrest_coverage.md"], "\n".join(da_report))
        staged["android_feature_audit.json"].write_text(json.dumps(android_stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        summary = {
            "phishing": phishing_stats,
            "hinglish": {**hinglish_stats, **hinglish_candidate_stats},
            "android": {key: value for key, value in android_stats.items() if key != "feature_columns"},
            "text_datasets_merged": False,
            "training_test_splits_created": False,
            "models_trained": False,
        }
        staged["preparation_summary.json"].write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report = [
            "# Dataset preparation report", "",
            "This report accompanies derived candidates only. Raw files are preserved; no model or train/test split was created.", "",
            "## Candidate policy", "",
            "The two text sources are emitted separately with `text`, `label_original`, `source_dataset`, `inferred_input_type`, `review_required`, and `review_reason`, plus source-row and duplicate/category audit metadata. No harmonized `label` is assigned and the datasets are not merged. Original binary label values are preserved as strings in the candidate schema.", "",
            "The phishing source documentation defines 1 as phishing and 0 as benign, and describes the combined data as URL, SMS, email, and HTML examples from multiple sources. The sample itself includes promotional/spam-like text; selected label-1 records with explicit promotional/paid-SMS/newsletter cues are flagged for human review, not relabeled. See the [source dataset card](https://huggingface.co/datasets/ealvaradob/phishing-dataset/commit/94efbffcb4e26305d8d68d507a39c8065c6d97e3).", "",
            "The Hinglish candidate has one row per normalized message, preserves all source category values as a sorted list, and flags category conflicts. `scam_category`, `caller_type`, `urgency_level`, and all other non-text metadata are excluded from this initial text candidate. The 743 unique strings are not claimed to be independent real-world observations.", "",
            "The official Android source description says the workbook contains APK-derived permission data from multiple repositories and app categories, but does not define the `OUTPUT` code polarity. Therefore `label_original` retains the raw 0/1 values and every Android row remains `review_required=true`; no malware/benign label is assigned. `Package` and `Category` are excluded from candidate features. See [Mendeley Data, version 2](https://data.mendeley.com/datasets/rvjptkrc34/2).", "",
            "## Preparation results", "",
            "```json", json.dumps(summary, ensure_ascii=False, indent=2), "```", "",
            "## Input type policy", "",
            "`html` requires an HTML doctype/structural tag. `email` requires explicit mail headers or recognizable newsletter/unsubscribe footer cues. `url` is used only when the entire text consists of URL/domain-like tokens. Remaining content is `plain_text`; the source does not prove SMS as the channel. Independent `content_signals` preserve embedded URL/email/HTML indicators. These rules are heuristics, not ground truth.", "",
            "## Leakage and review notes", "",
            "Duplicate texts remain traceable through SHA-256 group IDs and source row indices. Hinglish category conflicts are retained, not resolved. Android package conflicts are listed in a separate review CSV; records are not deleted. Android row index, labels, package identifiers, and app categories are metadata and must not enter the feature matrix. No split is created until label mapping and grouping policy are approved.", "",
            "## Reproduction", "",
            "From the repository root, run `python backend/notebooks/prepare_ml_datasets.py`. The script uses only the Python standard library and reads the existing extracted workbook in streaming mode. It replaces only its named output files under `backend/data/processed` after successful completion.",
        ]
        write_markdown(staged["dataset_preparation_report.md"], "\n".join(report))

        for name, target in outputs.items():
            os.replace(staged[name], target)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        for temp in staged.values():
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        print(f"Preparation failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
