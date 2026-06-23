import datetime
import json

from best_time_records import BestTimeRecordStore


def test_best_time_store_load_cleans_stale_and_invalid_records(tmp_path):
    path = tmp_path / "best_time_records.json"
    path.write_text(
        json.dumps(
            {
                "2026-06-23": 120,
                "2026-05-01": 90,
                "not-a-date": 80,
                "2026-06-22": "bad",
                "2026-06-21": 0,
            }
        ),
        encoding="utf-8",
    )
    store = BestTimeRecordStore(path)

    records = store.load(today=datetime.date(2026, 6, 23))

    assert records == {"2026-06-23": 120.0}
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted == {"2026-06-23": 120.0}


def test_best_time_store_update_only_persists_new_daily_best(tmp_path):
    path = tmp_path / "best_time_records.json"
    store = BestTimeRecordStore(path)
    today = datetime.date(2026, 6, 23)

    records = store.update_best_time({}, 120, today=today)
    unchanged = store.update_best_time(records, 130, today=today)
    improved = store.update_best_time(unchanged, 95, today=today)

    assert records == {"2026-06-23": 120.0}
    assert unchanged == {"2026-06-23": 120.0}
    assert improved == {"2026-06-23": 95.0}
    assert json.loads(path.read_text(encoding="utf-8")) == {"2026-06-23": 95.0}


def test_best_time_store_corrupt_file_loads_empty_without_overwriting(tmp_path):
    path = tmp_path / "best_time_records.json"
    path.write_text("{not-json}", encoding="utf-8")
    store = BestTimeRecordStore(path)

    assert store.load(today=datetime.date(2026, 6, 23)) == {}
    assert path.read_text(encoding="utf-8") == "{not-json}"
