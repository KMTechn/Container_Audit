"""Runtime import guards for optional native dependency removal."""

from __future__ import annotations

import atexit
import importlib.abc
import json
import os
from pathlib import Path
import sys


class _CharsetNormalizerBlocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        del path, target
        if fullname == "charset_normalizer" or fullname.startswith("charset_normalizer."):
            raise ModuleNotFoundError(
                "Container Audit uses the source-only chardet path instead of charset-normalizer",
                name=fullname,
            )
        return None


_BLOCKER = _CharsetNormalizerBlocker()
_MODULE_REPORT_ENV = "KMTECH_ZERO_PE_MODULE_REPORT"


def install_charset_normalizer_block() -> None:
    """Fail optional charset-normalizer imports before requests is loaded."""

    if not any(finder is _BLOCKER for finder in sys.meta_path):
        sys.meta_path.insert(0, _BLOCKER)


def _write_module_report() -> None:
    raw_path = os.getenv(_MODULE_REPORT_ENV, "").strip()
    if not raw_path:
        return
    target = Path(raw_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    families = ("PIL", "pygame", "charset_normalizer", "cryptography", "cffi")
    loaded = {
        family: sorted(
            name
            for name in sys.modules
            if name == family or name.startswith(f"{family}.")
        )
        for family in families
    }
    temporary = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    temporary.write_text(
        json.dumps({"loaded": loaded}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)


install_charset_normalizer_block()
atexit.register(_write_module_report)


__all__ = ["install_charset_normalizer_block"]
