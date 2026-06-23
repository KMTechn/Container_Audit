from __future__ import annotations

import csv
import json
import os
import re
from pathlib import Path
from typing import Any, Callable

from label_qr import canonical_master_label_key
from session_history import _validate_history_complete_details, _validate_history_replacement_details


def _master_label_matches(candidate: Any, requested: str) -> bool:
    return candidate == requested or canonical_master_label_key(candidate) == canonical_master_label_key(requested)


def _completion_details_valid(details: dict[str, Any]) -> bool:
    try:
        _validate_history_complete_details(details)
    except (TypeError, ValueError):
        return False
    return True


def _replacement_details_valid(
    details: dict[str, Any],
    *,
    stable_hash_func: Callable[[dict[str, Any]], str] | None = None,
) -> bool:
    try:
        _validate_history_replacement_details(
            details,
            stable_hash_func=stable_hash_func,
            require_projection=True,
        )
    except (TypeError, ValueError):
        return False
    return True


def replacement_log_file_paths(folder: str | os.PathLike[str]) -> list[str]:
    log_file_pattern = re.compile(r"(이적작업이벤트로그|검사작업이벤트로그)_.*_(\d{8})\.csv")
    ranked_paths: list[tuple[str, int, str, str]] = []
    for name in os.listdir(folder):
        path = Path(folder) / name
        if not path.is_file():
            continue
        match = log_file_pattern.fullmatch(name)
        if not match:
            continue
        prefix, date_text = match.groups()
        current_prefix_priority = 1 if prefix == "이적작업이벤트로그" else 0
        ranked_paths.append((date_text, current_prefix_priority, name, str(path)))
    ranked_paths.sort(reverse=True)
    return [path for _date_text, _prefix_priority, _name, path in ranked_paths]


def _superseded_hashes_from_replacement_details(details: dict[str, Any]) -> set[str]:
    hashes: set[str] = set()
    for key in ("old_row_hash",):
        value = details.get(key)
        if isinstance(value, str) and value:
            hashes.add(value)
    for key in ("supersedes_identity", "original_event_identity"):
        identity = details.get(key)
        if isinstance(identity, dict):
            value = identity.get("row_hash")
            if isinstance(value, str) and value:
                hashes.add(value)
    return hashes


def _source_record_matches_replacement(details: dict[str, Any], source_record: dict[str, Any]) -> bool:
    old_label = details.get("old_master_label")
    if isinstance(old_label, str) and old_label:
        if not _master_label_matches(source_record.get("master_label_code"), old_label):
            return False
    old_payload_hash = details.get("old_payload_hash")
    if isinstance(old_payload_hash, str) and old_payload_hash:
        if source_record.get("payload_hash") != old_payload_hash:
            return False
    return True


def _filter_superseded_hashes_for_known_sources(
    details: dict[str, Any],
    hashes: set[str],
    source_records_by_hash: dict[str, dict[str, Any]],
) -> set[str]:
    return {
        hash_value
        for hash_value in hashes
        if hash_value in source_records_by_hash
        and _source_record_matches_replacement(details, source_records_by_hash[hash_value])
    }


def _collect_supersedable_source_records(
    file_paths: list[str | os.PathLike[str]],
    *,
    stable_hash_func: Callable[[dict[str, Any]], str],
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for file_path in file_paths:
        path = Path(file_path)
        try:
            raw_lines = path.read_bytes().splitlines(keepends=True)
            byte_offsets: list[int] = []
            running_offset = len(raw_lines[0]) if raw_lines else 0
            for raw_line in raw_lines[1:]:
                byte_offsets.append(running_offset)
                running_offset += len(raw_line)
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                for idx, row in enumerate(reader):
                    try:
                        details = json.loads(row.get("details", "{}"))
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if not isinstance(details, dict):
                        continue
                    event = row.get("event")
                    if event == "TRAY_COMPLETE":
                        if not _completion_details_valid(details):
                            continue
                        row_number = idx + 2
                        byte_offset = byte_offsets[idx] if idx < len(byte_offsets) else None
                        row_hash = stable_hash_func(
                            {
                                "source_file_id": path.name,
                                "source_row_number": row_number,
                                "source_byte_offset": byte_offset,
                                "row": row,
                            }
                        )
                        records[row_hash] = {
                            "master_label_code": details.get("master_label_code"),
                            "payload_hash": stable_hash_func(details),
                        }
                    elif event == "MASTER_LABEL_REPLACEMENT_APPLIED":
                        if not _replacement_details_valid(details, stable_hash_func=stable_hash_func):
                            continue
                        projection = details.get("corrected_completion_projection")
                        new_row_hash = details.get("new_row_hash")
                        new_payload_hash = details.get("new_payload_hash")
                        if (
                            isinstance(projection, dict)
                            and isinstance(new_row_hash, str)
                            and new_row_hash
                            and isinstance(new_payload_hash, str)
                            and new_payload_hash
                        ):
                            records[new_row_hash] = {
                                "master_label_code": projection.get("master_label_code"),
                                "payload_hash": new_payload_hash,
                            }
        except Exception as exc:
            print(f"로그 파일 '{path.name}' 교체 source 해시 수집 중 오류: {exc}")
    return records


def collect_replacement_superseded_hashes(
    file_paths: list[str | os.PathLike[str]],
    *,
    stable_hash_func: Callable[[dict[str, Any]], str] | None = None,
) -> set[str]:
    hashes: set[str] = set()
    source_records_by_hash = (
        _collect_supersedable_source_records(file_paths, stable_hash_func=stable_hash_func)
        if stable_hash_func is not None
        else None
    )
    for file_path in file_paths:
        path = Path(file_path)
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    if row.get("event") != "MASTER_LABEL_REPLACEMENT_APPLIED":
                        continue
                    try:
                        details = json.loads(row.get("details", "{}"))
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if isinstance(details, dict) and _replacement_details_valid(
                        details,
                        stable_hash_func=stable_hash_func,
                    ):
                        superseded = _superseded_hashes_from_replacement_details(details)
                        if source_records_by_hash is not None:
                            superseded = _filter_superseded_hashes_for_known_sources(
                                details,
                                superseded,
                                source_records_by_hash,
                            )
                        hashes.update(superseded)
        except Exception as exc:
            print(f"로그 파일 '{path.name}' 교체 이력 수집 중 오류: {exc}")
    return hashes


def find_replacement_source_entry(
    file_path: str | os.PathLike[str],
    old_label: str,
    *,
    stable_hash_func: Callable[[dict[str, Any]], str],
    superseded_hashes: set[str] | None = None,
) -> dict[str, Any] | None:
    path = Path(file_path)
    try:
        raw_lines = path.read_bytes().splitlines(keepends=True)
        byte_offsets: list[int] = []
        running_offset = len(raw_lines[0]) if raw_lines else 0
        for raw_line in raw_lines[1:]:
            byte_offsets.append(running_offset)
            running_offset += len(raw_line)

        candidates: list[dict[str, Any]] = []
        source_records_by_hash: dict[str, dict[str, Any]] = {}
        all_superseded_hashes: set[str] = set(superseded_hashes or set())
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for idx, row in enumerate(reader):
                event = row.get("event")
                try:
                    details = json.loads(row.get("details", "{}"))
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(details, dict):
                    continue
                source_row_number = idx + 2
                source_byte_offset = byte_offsets[idx] if idx < len(byte_offsets) else None
                if event == "TRAY_COMPLETE":
                    if not _completion_details_valid(details):
                        continue
                    row_hash = stable_hash_func(
                        {
                            "source_file_id": path.name,
                            "source_row_number": source_row_number,
                            "source_byte_offset": source_byte_offset,
                            "row": row,
                        }
                    )
                    candidates.append(
                        {
                            "found_log_file": str(path),
                            "found_source_file_id": path.name,
                            "found_row_index": source_row_number,
                            "found_source_byte_offset": source_byte_offset,
                            "found_row_hash": row_hash,
                            "original_details": details,
                        }
                    )
                    source_records_by_hash[row_hash] = {
                        "master_label_code": details.get("master_label_code"),
                        "payload_hash": stable_hash_func(details),
                    }
                    continue
                if event != "MASTER_LABEL_REPLACEMENT_APPLIED":
                    continue

                if not _replacement_details_valid(details, stable_hash_func=stable_hash_func):
                    continue

                all_superseded_hashes.update(
                    _filter_superseded_hashes_for_known_sources(
                        details,
                        _superseded_hashes_from_replacement_details(details),
                        source_records_by_hash,
                    )
                )

                projection = details.get("corrected_completion_projection")
                new_row_hash = details.get("new_row_hash")
                if not isinstance(projection, dict) or not isinstance(new_row_hash, str) or not new_row_hash:
                    continue
                if not _completion_details_valid(projection):
                    continue
                identity = details.get("original_event_identity")
                if not isinstance(identity, dict):
                    identity = details.get("supersedes_identity") if isinstance(details.get("supersedes_identity"), dict) else {}
                candidates.append(
                    {
                        "found_log_file": str(path),
                        "found_source_file_id": identity.get("source_file_id") or path.name,
                        "found_row_index": identity.get("source_row_number") or source_row_number,
                        "found_source_byte_offset": identity.get("source_byte_offset", source_byte_offset),
                        "found_row_hash": new_row_hash,
                        "original_details": projection,
                    }
                )
                source_records_by_hash[new_row_hash] = {
                    "master_label_code": projection.get("master_label_code"),
                    "payload_hash": details.get("new_payload_hash"),
                }
        for candidate in reversed(candidates):
            row_hash = candidate.get("found_row_hash")
            if isinstance(row_hash, str) and row_hash in all_superseded_hashes:
                continue
            if _master_label_matches(candidate["original_details"].get("master_label_code"), old_label):
                return candidate
    except Exception as exc:
        print(f"로그 파일 '{path.name}' 검색 중 오류: {exc}")
    return None
