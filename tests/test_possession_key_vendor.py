import hashlib
import json
from pathlib import Path


VENDOR_ROOT = Path(__file__).resolve().parents[1] / "vendor" / "kmtech_zero_pe"
EXPECTED_SOURCE_COMMIT = "67db9569bcf7f1eacebeed664f00b4c51e48ff54"
EXPECTED_HASHES = {
    "__init__.py": "9b53fe7481609d85c4a686db53b847d3c6a38060051535fea157a5ee7c5d0f55",
    "cng_p256.py": "bd792c05e9f9c288469c92ecbdcdc088cc21dcfd7760c82ddcaa89ea48fc770b",
    "possession_key.py": "818355683e2c893b4b2afd368c08012f15b1fd18e60db5bdbddbfb254b2f3e73",
}


def test_possession_key_vendor_is_byte_pinned():
    metadata = json.loads((VENDOR_ROOT / "VENDOR.json").read_text(encoding="utf-8"))

    assert metadata == {
        "source_commit": EXPECTED_SOURCE_COMMIT,
        "source_path": "src/kmtech_zero_pe",
        "files": EXPECTED_HASHES,
    }
    assert {
        name: hashlib.sha256((VENDOR_ROOT / name).read_bytes()).hexdigest()
        for name in EXPECTED_HASHES
    } == EXPECTED_HASHES
