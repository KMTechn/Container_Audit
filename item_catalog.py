from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional

from product_identity_port import find_catalog_item, matching_catalog_codes


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
        return find_catalog_item(item_code, catalog_view=self._by_code)

    def find_in_barcode(self, barcode: str) -> Optional[Dict[str, Any]]:
        matches = self.matching_codes_in_barcode(barcode)
        if len(matches) != 1:
            return None
        return self.find_by_code(matches[0])

    def matching_codes_in_barcode(self, barcode: str) -> List[str]:
        return matching_catalog_codes(barcode, catalog_view=self._by_code)
