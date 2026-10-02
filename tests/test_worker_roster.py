"""Roster cache, selection and remote latency against the real admission guards."""
import datetime
import hashlib
import hmac
import json
import queue
import threading
import time
import uuid
from pathlib import Path
from types import MethodType, SimpleNamespace

import pytest

import Container_Audit as ca
from Container_Audit import ContainerAudit
from container_admin_pin import AdminPinError
from session_history import load_session_history
from tests.test_container_admin_pin import make_client
from tests.test_remembered_worker_start import _login, _registry
from tests.test_scanonly_review_regressions import public_scan, _pump_until
from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock, COMPACT_QR, ITEM
from worker_roster import WorkerRoster, CONTRACT_VERSION, MAX_CACHE_BYTES, MAX_RESPONSE_BYTES, _digest

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


def response(*rows, version=1):
    return {"ok": True, "contract_version": CONTRACT_VERSION, "authority_scope_id": "site-1",
            "version": version, "unchanged": False, "workers": list(rows)}


def row(name="tester", status="ACTIVE", worker_id=None):
    return {"worker_id": worker_id or str(uuid.uuid4()), "display_name": name, "status": status}


def store(tmp_path, *rows):
    roster = WorkerRoster(tmp_path / "config" / "roster.json", "site-1")
    roster.apply(response(*rows), requested_version=None)
    return roster


def test_signed_query_reuses_identity_and_nonce_with_separate_response_cap(monkeypatch):
    calls = []
    answer = response(row("Nguyễn Văn An"))
    answer["padding"] = "x" * 9000
    def transport(path, body, headers):
        calls.append((path, json.loads(body), headers["X-Producer-Nonce"]))
        signed = "\n".join((ca_admin.SIGNATURE_VERSION, "POST", path, "",
                            headers["X-Producer-Timestamp"], headers["X-Producer-Nonce"],
                            str(client.credentials.producer_id), str(client.credentials.key_id),
                            hashlib.sha256(body).hexdigest(), hashlib.sha256(body).hexdigest(),
                            str(len(body)), "application/json"))
        credential = client.credentials.secret
        expected = hmac.new(credential.encode() if isinstance(credential, str) else credential,
                            signed.encode(), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(expected, headers["X-Producer-Signature"])
        return 200, json.dumps(answer).encode()
    import container_admin_pin as ca_admin
    client = make_client(monkeypatch, transport)
    assert client.query_roster(authority_scope_id="site-1", known_version=None)["workers"] == answer["workers"]
    assert client.query_roster(authority_scope_id="site-1", known_version=1)["ok"]
    assert calls[0][:2] == ("/api/worker-roster/v1/query", {"authority_scope_id": "site-1", "known_version": None})
    assert calls[0][2] != calls[1][2]
    with pytest.raises(AdminPinError):
        client.post("redemptions/status", {})
    client.transport = lambda *args: (200, b" " * 262145)
    with pytest.raises(AdminPinError):
        client.query_roster(authority_scope_id="site-1", known_version=1)


def test_cache_unchanged_upgrade_and_offline_restart(tmp_path):
    original = row()
    roster = store(tmp_path, original, row("stopped", "DISABLED"), row("  "))
    assert roster.active_workers() == [original]
    unchanged = {name: value for name, value in response(version=1).items() if name != "workers"}
    unchanged["unchanged"] = True
    roster.apply(unchanged, requested_version=1)
    assert WorkerRoster(roster.path, "site-1").active_workers() == [original]
    replacement = row("새 사람")
    roster.apply(response(replacement, version=2), requested_version=1)
    assert WorkerRoster(roster.path, "site-1").active_workers() == [replacement]
    with pytest.raises(ValueError):
        roster.apply(unchanged, requested_version=1)


@pytest.mark.parametrize("damage", ["digest", "scope", "duplicate", "type", "json", "oversized"])
def test_corrupt_cache_preserves_original_and_uses_last_good(tmp_path, damage):
    original = row()
    roster = store(tmp_path, original)
    value = json.loads(roster.path.read_text(encoding="utf-8"))
    if damage == "digest":
        value["sha256"] = "0" * 64
    elif damage == "scope":
        value["authority_scope_id"] = "other-site"
    elif damage == "duplicate":
        value["workers"].append(value["workers"][0])
    elif damage == "type":
        value["version"] = True
    if damage not in {"digest", "json"}:
        value["sha256"] = _digest({name: item for name, item in value.items() if name != "sha256"})
    damaged = (b"not JSON" if damage == "json" else b"x" * (MAX_CACHE_BYTES + 1) if damage == "oversized"
               else json.dumps(value).encode())
    roster.path.write_bytes(damaged)
    restarted = WorkerRoster(roster.path, "site-1")
    assert restarted.active_workers() == [original]
    assert list(roster.path.parent.glob("roster.json.bad-*"))[0].read_bytes() == damaged


def test_large_valid_response_remains_a_valid_cache_on_restart(tmp_path):
    rows = [row(name=f"worker-{index:05d}-abcdefgh") for index in range(1800)]
    answer = response(*rows)
    assert len(json.dumps(answer, separators=(",", ":")).encode()) <= MAX_RESPONSE_BYTES
    roster = store(tmp_path, *rows)
    assert roster.path.stat().st_size > MAX_RESPONSE_BYTES
    restarted = WorkerRoster(roster.path, "site-1")
    assert restarted.active_workers() == rows
    assert not list(roster.path.parent.glob("*.bad-*"))


def test_invalid_reply_cannot_empty_the_cache(tmp_path):
    roster = store(tmp_path, row())
    before = roster.path.read_bytes()
    for answer in (None, {"ok": False}, response(row(), version=0), response(row(worker_id="wrong"))):
        with pytest.raises((TypeError, ValueError)):
            roster.apply(answer, requested_version=1)
        assert roster.path.read_bytes() == before
    no_cache = WorkerRoster(tmp_path / "empty.json", "site-1")
    with pytest.raises(ValueError):
        no_cache.apply({**response(), "unchanged": True}, requested_version=None)


@pytest.mark.parametrize("status", ["ACTIVE", "DISABLED", "absent", "offline", "replaced"])
def test_remembered_start_checks_roster_and_upgrades_legacy_id(flow, windows, tmp_path, status):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    screen, selected = _login(app, registry, tmp_path)
    worker = row(status=status if status in {"ACTIVE", "DISABLED"} else "ACTIVE")
    app.worker_roster = store(tmp_path, *( [row("another-worker")] if status == "absent" else [worker])) if status != "offline" else None
    if status == "replaced":
        registry.bind_worker_id("tester", str(uuid.uuid4()))
    starts = []
    app.start_work = lambda **kwargs: starts.append((selected["name"], kwargs))
    app._start_remembered_worker(registry.recent_worker())
    assert bool(starts) == (status in {"ACTIVE", "offline"})
    if status == "ACTIVE":
        assert registry.recent_worker_id() == worker["worker_id"]
        assert starts == [("tester", {"_automatic": True})]
    elif status in {"DISABLED", "absent", "replaced"}:
        assert not registry.automatic_start_enabled()
    assert windows == [] and screen["value"] == "selection"


def test_selection_is_roster_only_and_recent_order_is_by_id(flow, windows, tmp_path):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json", "local")
    _login(app, registry, tmp_path)
    first, recent, disabled = row("홍길"), row("Nguyễn Văn An"), row("stopped", "DISABLED")
    app.worker_roster = store(tmp_path, first, recent, disabled)
    registry.mark_recent(recent["display_name"], worker_id=recent["worker_id"])
    assert app._worker_selection_names() == [recent["display_name"], first["display_name"]]
    assert app._ensure_worker_login_name("new typed name") is None
    assert app._ensure_worker_login_name("local") is None
    assert app._ensure_worker_login_name(recent["display_name"]) == recent["display_name"]
    assert app._selected_roster_id == recent["worker_id"]
    assert windows == []


def test_temporarily_selects_existing_local_names_without_registration(flow, windows, tmp_path):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    assert app._worker_selection_names() == ["tester"]
    assert "이 PC" in app._worker_roster_notice_text()
    assert app._ensure_worker_login_name("tester") == "tester"
    assert app._ensure_worker_login_name("unlisted") is None
    assert not hasattr(ContainerAudit, "register_worker_from_login")
    assert windows == []


def test_actual_selector_has_no_edit_or_registration_control(flow, tmp_path, monkeypatch):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    class Widget:
        def __init__(self, *args, **kwargs):
            self.options = kwargs
        def pack(self, *args, **kwargs): pass
        def grid(self, *args, **kwargs): pass
        def grid_rowconfigure(self, *args, **kwargs): pass
        def grid_columnconfigure(self, *args, **kwargs): pass
        def bind(self, *args, **kwargs): pass
        def focus(self): pass
        def winfo_children(self): return []
        def get(self): return self.options["textvariable"].get()
        def configure(self, **kwargs): self.options.update(kwargs)
    app.worker_input_frame = Widget()
    app.scale_factor = 1.0
    app._clear_main_frames = lambda: None
    app._apply_worker_login_layout = lambda: None
    app._refresh_worker_roster = lambda: None
    monkeypatch.setattr(ca.tk, "StringVar", lambda value: SimpleNamespace(get=lambda: value))
    for name in ("Frame", "Label", "Button", "Combobox"):
        monkeypatch.setattr(ca.ttk, name, Widget)
    ContainerAudit.show_worker_input_screen(app)
    assert app.worker_entry.options["state"] == "readonly"
    assert [button.options["text"] for button in app._worker_login_buttons] == ["관리자", "작업 시작"]
    assert app.worker_entry.options["values"] == ["tester"]


@pytest.mark.parametrize("name", ["홍길", "홍길동", "Alex", "Nguyễn Văn An", "외국 이름" * 100, "외국/이름", "=Alex"])
def test_selected_name_is_preserved_in_session_scan_and_history(flow, windows, tmp_path, name):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    chosen = row(name)
    app.worker_roster = store(tmp_path, chosen)
    app._refresh_worker_roster = lambda: None
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    app._set_worker_entry_value(name)
    app.start_work()
    public_scan(app, COMPACT_QR + "|QT=2")
    public_scan(app, ITEM + "-SERIAL-001")
    state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
    assert state["worker_name"] == name
    assert "worker_id" not in state
    assert app._load_work_session_state()["worker_name"] == name
    history = load_session_history(save_folder=app.save_folder, worker_name=name,
                                   today=datetime.date.today(), tray_size=app.TRAY_SIZE)
    assert len(Path(history.log_file_path).name.encode("utf-16-le")) < 510
    assert windows == []


def test_disabled_worker_finishes_current_tray_then_selects_before_next(flow, windows, tmp_path):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    screen, _ = _login(app, registry, tmp_path)
    worker = row()
    app.worker_roster = store(tmp_path, worker)
    app._refresh_worker_roster = lambda: None
    app.start_work()
    public_scan(app, COMPACT_QR + "|QT=1")
    app.worker_roster.apply(response({**worker, "status": "DISABLED"}, version=2), requested_version=1)
    public_scan(app, ITEM + "-SERIAL-001")
    assert app.total_tray_count == 1
    assert not app._roster_allows_new_tray()
    assert screen["value"] == "selection" and not registry.automatic_start_enabled()
    assert windows == []


@pytest.mark.parametrize("fail", [False, True])
def test_six_second_roster_request_does_not_delay_scan_or_hold_writer_lock(flow, windows, tmp_path, fail):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    worker = row()
    app.worker_roster = store(tmp_path, worker)
    app._refresh_worker_roster = lambda: None
    app.start_work()
    public_scan(app, COMPACT_QR + "|QT=2")
    entered = threading.Event()
    def slow(path, body, headers):
        entered.set()
        time.sleep(6)
        if fail:
            raise ConnectionError("synthetic disconnection")
        return 200, json.dumps(response(worker)).encode()
    # A real signed client passes the suite's lock/remote detector.
    from unittest.mock import patch
    with patch("container_admin_pin.load_credentials_from_json", return_value=SimpleNamespace(
            endpoint_url="https://roster.example.test/api/producer-ingest/v1", producer_id="producer-1",
            key_id="roster-fixture", secret=uuid.uuid4().hex * 2, tls_ca_bundle_path="")):
        from container_admin_pin import AdminPinClient
        app._admin_pin_client = AdminPinClient("unused.json", transport=slow)
    try:
        ContainerAudit._refresh_worker_roster(app)
        assert entered.wait(2)
        started = time.monotonic()
        public_scan(app, ITEM + "-SERIAL-001")
        elapsed = time.monotonic() - started
        state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
        assert state["scanned_barcodes"] == [ITEM + "-SERIAL-001"]
        assert elapsed < 1
    finally:
        app._roster_thread.join(10)
    assert not app._roster_thread.is_alive()
    _pump_until(app.root, lambda: getattr(app, "_roster_refresh_job", None) is not None)
    assert app.worker_roster.active_workers() == [worker]
    assert windows == []


def test_refresh_cancels_old_timer_even_when_query_is_pending():
    app = ContainerAudit.__new__(ContainerAudit)
    cancelled = []
    app.root = SimpleNamespace(after_cancel=cancelled.append)
    app.worker_roster = SimpleNamespace(known_version=1)
    app._roster_refresh_job = "old-periodic-job"
    app._roster_pending_epoch = ""
    app._roster_thread = SimpleNamespace(is_alive=lambda: True)
    app._refresh_worker_roster()
    assert cancelled == ["old-periodic-job"]
    assert app._roster_refresh_job is None


def test_background_disabled_reply_keeps_owner_and_durably_disables_next_start(flow, windows, tmp_path):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    worker = row()
    app.worker_roster = store(tmp_path, worker)
    app._refresh_worker_roster = lambda: None
    app.start_work()
    public_scan(app, COMPACT_QR + "|QT=2")
    owner = app.worker_name
    replies = queue.Queue()
    replies.put(response({**worker, "status": "DISABLED"}, version=2))
    app._roster_attempt = "current"
    app._poll_worker_roster(replies, "current", app._admin_pin_login_epoch, 1)
    assert app.worker_name == owner and app.current_tray.master_label_code
    assert not registry.automatic_start_enabled()
    public_scan(app, ITEM + "-SERIAL-001")
    assert app.current_tray.scanned_barcodes == [ITEM + "-SERIAL-001"]
    assert windows == []


def test_fence_during_local_cache_apply_preserves_cache_and_periodic_retry(flow, windows, tmp_path, monkeypatch):
    from writer_session_fence import WriterFencedError
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    app.worker_roster = store(tmp_path, row())
    before = app.worker_roster.path.read_bytes()
    def fenced(*args, **kwargs):
        raise WriterFencedError("TEST_FENCE", "synthetic deployment fence")
    monkeypatch.setattr(app.worker_roster, "apply", fenced)
    replies = queue.Queue()
    replies.put(response(version=2))
    app._roster_attempt = "current"
    app._admin_pin_login_epoch = "login"
    app._poll_worker_roster(replies, "current", "login", 1)
    assert app.worker_roster.path.read_bytes() == before
    assert app._roster_refresh_job is not None
    assert windows == []


@pytest.mark.parametrize("changed", ["attempt", "login"])
def test_late_reply_cannot_change_cache_or_selection(flow, windows, tmp_path, changed):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    app.worker_roster = store(tmp_path, row())
    before = app.worker_roster.path.read_bytes()
    replies = queue.Queue()
    replies.put(response(row("late"), version=2))
    app._roster_attempt = "current"
    app._admin_pin_login_epoch = "new-login"
    app._poll_worker_roster(replies, "old" if changed == "attempt" else "current", "old-login", 1)
    assert app.worker_roster.path.read_bytes() == before
    assert app._worker_selection_names() == ["tester"]
    assert windows == []


@pytest.mark.parametrize("restart", [False, True], ids=["online", "offline-cache"])
def test_normal_empty_roster_keeps_local_selection_and_remembered_start(flow, windows, tmp_path, restart):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    app.worker_roster = WorkerRoster(tmp_path / "config" / "roster.json", "site-1")
    if restart:
        app.worker_roster.apply(response(), requested_version=None)
        app.worker_roster = WorkerRoster(app.worker_roster.path, "site-1")
    else:
        replies = queue.Queue()
        replies.put(response())
        app._roster_attempt = "current"
        app._admin_pin_login_epoch = "login"
        app._poll_worker_roster(replies, "current", "login", None)
    assert app.worker_roster.snapshot is not None and not app.worker_roster.has_rows
    assert app._worker_selection_names() == ["tester"]
    assert "이 PC" in app._worker_roster_notice_text()
    assert registry.automatic_start_enabled()
    app._refresh_worker_roster = lambda: None
    app._start_remembered_worker(registry.recent_worker())
    assert app.worker_name == "tester" and app._work_session_identity_bound
    assert app._roster_allows_new_tray()
    assert windows == []


@pytest.mark.parametrize("invalid", [False, True], ids=["all-disabled", "all-invalid"])
@pytest.mark.parametrize("restart", [False, True], ids=["online", "offline-cache"])
def test_nonempty_roster_without_selectable_rows_never_falls_back(flow, windows, tmp_path, invalid, restart):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    _login(app, registry, tmp_path)
    worker = row("bad" + chr(0x200b) + "name" if invalid else "tester", "ACTIVE" if invalid else "DISABLED")
    app.worker_roster = store(tmp_path, worker)
    if restart:
        app.worker_roster = WorkerRoster(app.worker_roster.path, "site-1")
    assert app.worker_roster.has_rows and app.worker_roster.snapshot["source_row_count"] == 1
    assert app._worker_selection_names() == []
    assert "이 PC" not in app._worker_roster_notice_text()
    starts = []
    app.start_work = lambda **kwargs: starts.append(kwargs)
    app._start_remembered_worker(registry.recent_worker())
    assert starts == [] and not registry.automatic_start_enabled()
    assert windows == []


@pytest.mark.parametrize("bad_name", ["", "   "] + ["bad" + chr(code) + "name" for code in (10, 0x200b, 0xd800, 0x2028, 0x2029)],
                         ids=["empty", "whitespace", "Cc", "Cf", "Cs", "Zl", "Zp"])
def test_invalid_name_row_is_discarded_without_losing_trimmed_valid_row(tmp_path, bad_name):
    valid = row("  Nguyễn Văn  ")
    invalid = row(bad_name)
    roster = store(tmp_path, invalid, valid)
    expected = {**valid, "display_name": "Nguyễn Văn"}
    assert roster.active_workers() == [expected]
    assert roster.snapshot["source_row_count"] == 2
    roster.apply({"ok": True, "contract_version": CONTRACT_VERSION, "authority_scope_id": "site-1",
                  "version": 1, "unchanged": True}, requested_version=1)
    restarted = WorkerRoster(roster.path, "site-1")
    assert restarted.active_workers() == [expected] and restarted.snapshot["source_row_count"] == 2
    with pytest.raises(ValueError):
        _registry(tmp_path / "workers.json").register(bad_name)


def test_legacy_cache_without_source_count_still_loads(tmp_path):
    worker = row()
    roster = store(tmp_path, worker)
    value = json.loads(roster.path.read_text())
    value.pop("source_row_count")
    value["sha256"] = _digest({name: item for name, item in value.items() if name != "sha256"})
    roster.path.write_text(json.dumps(value), encoding="utf-8")
    restarted = WorkerRoster(roster.path, "site-1")
    assert restarted.has_rows and restarted.active_workers() == [worker]
