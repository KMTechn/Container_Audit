from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional


class ItemCatalog:
    """Lookup wrapper for Item.csv rows."""

    def __init__(self, rows: Iterable[Mapping[str, Any]]):
        self.source_id = id(rows)
        self._rows: List[Dict[str, Any]] = []
        self._by_code: Dict[str, Dict[str, Any]] = {}
        for source_row in rows:
            row = dict(source_row)
            code = str(row.get("Item Code") or "").strip()
            if code:
                row["Item Code"] = code
            self._rows.append(row)
            if code and code not in self._by_code:
                self._by_code[code] = row

    def rows(self) -> List[Dict[str, Any]]:
        return [dict(row) for row in self._rows]

    def find_by_code(self, item_code: str) -> Optional[Dict[str, Any]]:
        return self._by_code.get(str(item_code or "").strip())

    def find_in_barcode(self, barcode: str) -> Optional[Dict[str, Any]]:
        matches = self.matching_codes_in_barcode(barcode)
        if len(matches) != 1:
            return None
        return self.find_by_code(matches[0])

    def matching_codes_in_barcode(self, barcode: str) -> List[str]:
        text = str(barcode or "")
        spans_by_code: Dict[str, List[tuple[int, int]]] = {}
        for code in self._by_code:
            start = 0
            spans: List[tuple[int, int]] = []
            while True:
                index = text.find(code, start)
                if index < 0:
                    break
                spans.append((index, index + len(code)))
                start = index + 1
            if spans:
                spans_by_code[code] = spans

        matches: List[str] = []
        for code, spans in spans_by_code.items():
            longer_spans = [
                other_span
                for other_code, other_spans in spans_by_code.items()
                if other_code != code and len(other_code) > len(code)
                for other_span in other_spans
            ]
            if longer_spans and all(
                any(other_start <= start and end <= other_end for other_start, other_end in longer_spans)
                for start, end in spans
            ):
                continue
            matches.append(code)
        return matches
