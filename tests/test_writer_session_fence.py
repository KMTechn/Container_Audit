from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

import writer_session_fence as fence


WINPS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
ROOT = Path(__file__).resolve().parents[1]
PS_HELPER = ROOT / "tools" / "container_writer_fence.ps1"


def _utc(offset_seconds: int = 0) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    ).isoformat().replace("+00:00", "Z")


def _active_payload(*, token: str = "", sources: list[str] | None = None) -> dict[str, object]:
    selected_sources = sorted(sources or [])
    session_id = "0" * 32
    attempt_id = "1" * 32
    orchestrator_sha256 = "2" * 64
    transaction_id = "3" * 32
    contract_sha256 = "4" * 64
    return {
        "schema": fence.ACTIVE_SCHEMA,
        "status": "PREPARING",
        "app_id": fence.APP_ID,
        "session_id": session_id,
        "attempt_id": attempt_id,
        "replacement_transaction_id": transaction_id,
        "session_started_at_utc": _utc(-1),
        "orchestrator_sha256": orchestrator_sha256,
        "writer_contract_sha256": contract_sha256,
        "session_authority_mutex_name": fence.session_authority_mutex_name(
            session_id,
            attempt_id,
            orchestrator_sha256,
            transaction_id,
            contract_sha256,
        ),
        "writer_inventory_sha256": fence.WRITER_INVENTORY_SHA256,
        "owner_kind": "session_adapter",
        "prepared_receipt_path": "",
        "prepared_receipt_sha256": "",
        "delegation_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest() if token else "",
        "delegated_sources": selected_sources,
        "delegation_expires_at_utc": _utc(60) if selected_sources else "",
        "activated_at_utc": _utc(),
        "secret_values_recorded": False,
    }


def _write_active(root: Path, payload: dict[str, object]) -> Path:
    root.mkdir(parents=True)
    if not payload.get("prepared_receipt_sha256"):
        receipt = root / "prepared.json"
        receipt.write_text('{"status":"PREPARED"}\n', encoding="utf-8")
        if payload.get("delegated_sources"):
            payload["status"] = "INSTALLING"
        payload["prepared_receipt_path"] = str(receipt.resolve())
        payload["prepared_receipt_sha256"] = hashlib.sha256(
            receipt.read_bytes()
        ).hexdigest()
    path = root / fence.ACTIVE_FILENAME
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_contract_verification_vectors_match_python_derivation() -> None:
    contract = json.loads((ROOT / "tools" / "container_writer_session_contract.json").read_text(encoding="utf-8"))
    vectors = contract["all_writer_fence"]["verification_vectors"]
    assert len(vectors) == 2
    for vector in vectors:
        assert vector["expected_mutex_name"] == fence.session_authority_mutex_name(
            vector["session_id"],
            vector["attempt_id"],
            vector["orchestrator_sha256"],
            vector["replacement_transaction_id"],
            vector["writer_contract_sha256"],
        )


@pytest.mark.skipif(not WINPS.exists(), reason="Windows PowerShell 5.1 is required")
def test_noncanonical_admission_mutex_derivation_matches_winps_for_unicode_roots(
    tmp_path: Path,
) -> None:
    roots = [
        tmp_path / "MixedCase" / "Fence",
        tmp_path / "Cafe\u0301",
        tmp_path / "Café",
        tmp_path / "ẞ",
    ]
    quoted_helper = str(PS_HELPER).replace("'", "''")
    commands = [f". '{quoted_helper}'"]
    commands.extend(
        "Get-ContainerWriterAdmissionMutexName -ControlRoot '"
        + str(root).replace("'", "''")
        + "'"
        for root in roots
    )
    completed = subprocess.run(
        [
            str(WINPS),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "; ".join(commands),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    actual = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    expected = [
        fence.writer_admission_mutex_name(root, environ={})
        for root in roots
    ]
    assert actual == expected
    assert expected[1] == expected[2]


def test_code_derived_inventory_pin_is_exact_across_all_fence_consumers() -> None:
    contract = json.loads(
        (ROOT / "tools" / "container_writer_session_contract.json").read_text(
            encoding="utf-8"
        )
    )
    inventory = json.loads(
        (ROOT / "tools" / "container_writer_sink_inventory.json").read_text(
            encoding="utf-8"
        )
    )
    expected = inventory["inventory_sha256"]
    assert expected != "0" * 64
    assert contract["all_writer_fence"]["writer_inventory_sha256"] == expected
    assert fence.WRITER_INVENTORY_SHA256 == expected
    assert (
        f"$Script:ContainerWriterFenceInventorySha256 = '{expected}'"
        in PS_HELPER.read_text(encoding="utf-8")
    )
    installer = (ROOT / "INSTALL_CANONICAL_PORTABLE.ps1").read_text(
        encoding="utf-8"
    )
    assert "ExpectedWriterInventorySha256" in installer
    assert "writer_sink_inventory_contract_sha256" in installer


def test_absent_fence_admits_and_active_fence_denies_without_mutation(tmp_path: Path) -> None:
    root = tmp_path / "control"
    target = tmp_path / "effect.txt"

    with fence.writer_admission("test_sink", control_root=root):
        target.write_text("positive", encoding="utf-8")
    assert target.read_text(encoding="utf-8") == "positive"

    active = _write_active(root, _active_payload())
    before = (active.read_bytes(), active.stat().st_mtime_ns, target.read_bytes())
    with pytest.raises(fence.WriterFencedError) as exc_info:
        with fence.writer_admission("test_sink", control_root=root):
            target.write_text("mutated", encoding="utf-8")
    assert exc_info.value.code == "ACTIVE_WRITER_FENCE"
    assert (active.read_bytes(), active.stat().st_mtime_ns, target.read_bytes()) == before


def test_malformed_fence_denies_and_releases_admission_mutex(tmp_path: Path) -> None:
    root = tmp_path / "control"
    active = _write_active(root, _active_payload())
    active.write_text("{", encoding="utf-8")
    before = (active.read_bytes(), active.stat().st_mtime_ns)
    with pytest.raises(fence.WriterFenceError) as exc_info:
        with fence.writer_admission("test_sink", control_root=root):
            raise AssertionError("unreachable")
    assert exc_info.value.code == "FENCE_JSON_INVALID"
    # A second call must reach the same JSON failure, not leak the mutex and time out.
    with pytest.raises(fence.WriterFenceError) as second:
        with fence.writer_admission("test_sink", control_root=root, timeout_seconds=0.1):
            raise AssertionError("unreachable")
    assert second.value.code == "FENCE_JSON_INVALID"
    assert (active.read_bytes(), active.stat().st_mtime_ns) == before


def test_installing_delegation_without_prepared_receipt_denies_zero_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "control"
    root.mkdir(parents=True)
    payload = _active_payload(token="i" * 48, sources=["install_sink"])
    payload["status"] = "INSTALLING"
    active = root / fence.ACTIVE_FILENAME
    active.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    effect = tmp_path / "effect.txt"
    before = active.read_bytes()

    with pytest.raises(fence.WriterFenceError) as exc_info:
        with fence.writer_admission("install_sink", control_root=root, environ={}):
            effect.write_text("bad", encoding="utf-8")
    assert exc_info.value.code == "FENCE_PREPARED_BINDING_INVALID"
    assert not effect.exists()
    assert active.read_bytes() == before


def test_delegation_requires_exact_source_token_tuple_and_live_authority(tmp_path: Path) -> None:
    root = tmp_path / "control"
    token = "t" * 48
    payload = _active_payload(token=token, sources=["delegated_sink"])
    _write_active(root, payload)
    ready = threading.Event()
    release = threading.Event()

    def hold_authority() -> None:
        lease = fence._acquire_named_mutex(payload["session_authority_mutex_name"], 1.0)
        assert lease is not None and not lease.abandoned
        ready.set()
        release.wait(10)
        lease.release()

    thread = threading.Thread(target=hold_authority, daemon=True)
    thread.start()
    assert ready.wait(5)
    environment = {
        fence.DELEGATION_TOKEN_ENV: token,
        fence.DELEGATION_SESSION_ENV: payload["session_id"],
        fence.DELEGATION_ATTEMPT_ENV: payload["attempt_id"],
        fence.DELEGATION_TRANSACTION_ENV: payload["replacement_transaction_id"],
    }
    try:
        with fence.writer_admission(
            "delegated_sink", control_root=root, environ=environment
        ):
            pass
        for key, value in (
            (fence.DELEGATION_TOKEN_ENV, "wrong" * 12),
            (fence.DELEGATION_SESSION_ENV, "9" * 32),
        ):
            invalid = dict(environment)
            invalid[key] = value
            with pytest.raises(fence.WriterFencedError):
                with fence.writer_admission(
                    "delegated_sink", control_root=root, environ=invalid
                ):
                    raise AssertionError("unreachable")
        with pytest.raises(fence.WriterFencedError):
            with fence.writer_admission(
                "different_sink", control_root=root, environ=environment
            ):
                raise AssertionError("unreachable")
    finally:
        release.set()
        thread.join(5)


@pytest.mark.skipif(not WINPS.exists(), reason="Windows PowerShell 5.1 is required")
def test_powershell_delegated_operation_requires_exact_live_source_tuple(
    tmp_path: Path,
) -> None:
    root = tmp_path / "control"
    token = "p" * 64
    payload = _active_payload(
        token=token,
        sources=["canonical_code_placement"],
    )
    _write_active(root, payload)
    ready = threading.Event()
    release = threading.Event()

    def hold_authority() -> None:
        lease = fence._acquire_named_mutex(
            payload["session_authority_mutex_name"],
            1.0,
        )
        assert lease is not None and not lease.abandoned
        ready.set()
        release.wait(10)
        lease.release()

    thread = threading.Thread(target=hold_authority, daemon=True)
    thread.start()
    assert ready.wait(5)
    quoted_helper = str(PS_HELPER).replace("'", "''")
    quoted_root = str(root).replace("'", "''")

    def invoke(source: str) -> subprocess.CompletedProcess[str]:
        script = (
            f". '{quoted_helper}'; "
            "$lease = Enter-ContainerWriterDelegatedOperation "
            f"-ControlRoot '{quoted_root}' "
            f"-SessionId '{payload['session_id']}' "
            f"-AttemptId '{payload['attempt_id']}' "
            f"-ReplacementTransactionId '{payload['replacement_transaction_id']}' "
            f"-DelegationToken '{token}' -Source '{source}'; "
            "Exit-ContainerWriterAdmission $lease; 'PASS'"
        )
        return subprocess.run(
            [str(WINPS), "-NoProfile", "-NonInteractive", "-Command", script],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    try:
        admitted = invoke("canonical_code_placement")
        assert admitted.returncode == 0, admitted.stdout + admitted.stderr
        assert "PASS" in admitted.stdout
        wrong_source = invoke("different_source")
        assert wrong_source.returncode != 0
        assert "DELEGATED_OPERATION_MISMATCH" in (
            wrong_source.stdout + wrong_source.stderr
        )
    finally:
        release.set()
        thread.join(5)


def test_decorator_exposes_source_and_blocks_body_zero_mutation(tmp_path: Path) -> None:
    root = tmp_path / "control"
    effect = tmp_path / "effect.txt"
    _write_active(root, _active_payload())

    @fence.writer_sink("decorated_test_sink")
    def mutate() -> None:
        effect.write_text("bad", encoding="utf-8")

    assert mutate.__container_writer_sink__ == "decorated_test_sink"
    old = os.environ.get("LOCALAPPDATA")
    os.environ["LOCALAPPDATA"] = str(tmp_path)
    canonical = fence.canonical_control_root()
    canonical.parent.mkdir(parents=True, exist_ok=True)
    # Move the fixture to the production-derived test root used by the decorator.
    canonical.mkdir(parents=True, exist_ok=True)
    (canonical / fence.ACTIVE_FILENAME).write_bytes((root / fence.ACTIVE_FILENAME).read_bytes())
    before = (canonical / fence.ACTIVE_FILENAME).read_bytes()
    try:
        with pytest.raises(fence.WriterFencedError):
            mutate()
    finally:
        if old is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = old
    assert not effect.exists()
    assert (canonical / fence.ACTIVE_FILENAME).read_bytes() == before


def test_writer_sink_rejects_async_and_generator_bodies() -> None:
    with pytest.raises(TypeError, match="synchronously"):

        @fence.writer_sink("async_sink")
        async def async_sink() -> None:
            return None

    with pytest.raises(TypeError, match="synchronously"):

        @fence.writer_sink("generator_sink")
        def generator_sink():
            yield "mutation"


def test_probe_only_admission_is_refused_for_every_unapproved_sink() -> None:
    assert fence.PROBE_ONLY_WRITER_SINKS == frozenset(
        {
            (
                "session_direct_sync_process",
                "direct_sync_auto_bootstrap.run_session_direct_sync_once",
            ),
            (
                "session_direct_sync_process",
                "direct_sync_auto_bootstrap._run_command",
            ),
            ("persistent_relay_status", "user_relay.main"),
        }
    )

    with pytest.raises(fence.WriterFencedError) as exc_info:

        @fence.writer_sink("session_direct_sync_process", probe_only=True)
        def foreign_sink() -> None:
            return None

    assert exc_info.value.code == "WRITER_PROBE_ONLY_SINK_NOT_ALLOWED"

    with pytest.raises(fence.WriterFencedError) as exc_info:

        @fence.writer_sink("direct_sync_install_pack", probe_only=True)
        def _run_command() -> None:
            return None

    assert exc_info.value.code == "WRITER_PROBE_ONLY_SINK_NOT_ALLOWED"


def test_probe_only_session_sink_denies_under_fence_before_any_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import direct_sync_auto_bootstrap as bootstrap

    root = tmp_path / "control"
    _write_active(root, _active_payload())
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    canonical = fence.canonical_control_root()
    canonical.mkdir(parents=True, exist_ok=True)
    active = canonical / fence.ACTIVE_FILENAME
    active.write_bytes((root / fence.ACTIVE_FILENAME).read_bytes())
    before = (active.read_bytes(), active.stat().st_mtime_ns)
    spawns: list[object] = []

    def forbidden_run(*args: object, **kwargs: object) -> None:
        spawns.append(args)
        raise AssertionError("the relay child must not be spawned under an active fence")

    monkeypatch.setattr(bootstrap.subprocess, "run", forbidden_run)

    with pytest.raises(fence.WriterFencedError) as exc_info:
        bootstrap.run_session_direct_sync_once(
            app_root=ROOT,
            direct_sync_root=tmp_path / "direct-sync",
            scan_source_dir=tmp_path / "events",
        )
    assert exc_info.value.code == "ACTIVE_WRITER_FENCE"

    with pytest.raises(fence.WriterFencedError) as exc_info:
        bootstrap._run_command(["relay"], 10)
    assert exc_info.value.code == "ACTIVE_WRITER_FENCE"

    assert spawns == []
    assert (active.read_bytes(), active.stat().st_mtime_ns) == before


def _admission_available_in_other_process(mutex_name: str) -> bool:
    result = subprocess.run(
        [
            sys.executable, "-B", "-c",
            "import sys; import writer_session_fence as f; "
            "lease=f._acquire_named_mutex(sys.argv[1], 0.25); "
            "available=lease is not None; "
            "lease.release() if available else None; "
            "sys.exit(0 if available else 7)",
            mutex_name,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode in {0, 7}, result.stderr
    return result.returncode == 0


@pytest.mark.parametrize("mode", ["gui", "relay"])
@pytest.mark.skipif(os.name != "nt", reason="cross-process Windows mutex semantics required")
def test_product_entrypoint_releases_admission_before_resident_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    import Container_Audit as app
    import user_relay
    from types import SimpleNamespace

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(tmp_path / "state"))
    mutex = fence.WRITER_MUTEX_NAME + ".resident-test." + hashlib.sha256(
        str(tmp_path).encode()
    ).hexdigest()[:16]
    monkeypatch.setattr(fence, "writer_admission_mutex_name", lambda *a, **k: mutex)
    events: list[str] = []

    def resident_loop(*args, **kwargs):
        assert _admission_available_in_other_process(mutex), (
            "the real product entrypoint must not hold admission for a resident loop"
        )
        events.append("resident")
        return {"last_cycle": {"status": "PASS"}}

    if mode == "relay":
        monkeypatch.setattr(user_relay, "run_persistent_relay_loop", resident_loop)
        assert app.main(["--container-audit-user-relay", "--app-root", str(ROOT)]) == 0
        assert events == ["resident"]
    else:
        def create_app():
            assert not _admission_available_in_other_process(mutex), (
                "GUI initialization must still retain writer admission"
            )
            events.append("initialize")
            return SimpleNamespace(
                root=SimpleNamespace(after=lambda *_: None), run=resident_loop,
            )

        monkeypatch.setattr(app, "verify_factory_contract_startup", lambda: None)
        monkeypatch.setattr(app, "_first_run_onboarding_enabled", lambda: False)
        monkeypatch.setattr(app, "prepare_startup_item_catalog", lambda: None)
        monkeypatch.setattr(app, "ContainerAudit", create_app)
        monkeypatch.setattr(app, "acquire_runtime_instance", lambda _: SimpleNamespace(
            release=lambda: events.append("instance-release"),
        ))
        assert app.main([]) == 0
        assert events == ["initialize", "resident", "instance-release"]


@pytest.mark.parametrize("arguments", [[], ["--container-audit-user-relay"]])
def test_product_entrypoint_denies_active_fence_before_gui_or_relay_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arguments: list[str],
) -> None:
    import Container_Audit as app
    import user_relay

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(tmp_path / "state"))
    active = _write_active(fence.canonical_control_root(), _active_payload())
    before = active.read_bytes()
    entered: list[str] = []
    monkeypatch.setattr(app, "verify_factory_contract_startup", lambda: entered.append("gui"))
    monkeypatch.setattr(user_relay, "run_persistent_relay_loop", lambda **_: entered.append("relay"))
    # A fenced relay's diagnostic writer must also be denied; neither mode
    # may turn an admission failure into a successful startup.
    with pytest.raises(fence.WriterFencedError, match="active deployment fence"):
        app.main(arguments)
    assert entered == []
    assert not (tmp_path / "state").exists()
    assert active.read_bytes() == before


def test_nested_sink_revalidates_its_own_source_and_preserves_zero_mutation(tmp_path: Path) -> None:
    root = tmp_path / "control"
    effect = tmp_path / "nested-effect.txt"
    token = "n" * 48
    payload = _active_payload(token=token, sources=["outer_sink"])
    _write_active(root, payload)
    ready = threading.Event()
    release = threading.Event()

    def hold_authority() -> None:
        lease = fence._acquire_named_mutex(payload["session_authority_mutex_name"], 1.0)
        assert lease is not None and not lease.abandoned
        ready.set()
        release.wait(10)
        lease.release()

    thread = threading.Thread(target=hold_authority, daemon=True)
    thread.start()
    assert ready.wait(5)
    environment = {
        fence.DELEGATION_TOKEN_ENV: token,
        fence.DELEGATION_SESSION_ENV: payload["session_id"],
        fence.DELEGATION_ATTEMPT_ENV: payload["attempt_id"],
        fence.DELEGATION_TRANSACTION_ENV: payload["replacement_transaction_id"],
    }
    try:
        with fence.writer_admission("outer_sink", control_root=root, environ=environment):
            with pytest.raises(fence.WriterFencedError) as exc_info:
                with fence.writer_admission("inner_sink", control_root=root, environ=environment):
                    effect.write_text("bad", encoding="utf-8")
        assert exc_info.value.code == "ACTIVE_WRITER_FENCE"
        assert not effect.exists()
    finally:
        release.set()
        thread.join(5)


def _writer_depth() -> int:
    return int(getattr(fence._WRITER_LOCAL, "depth", 0))


def _spy_on_admission_mutex(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    acquired: list[str] = []
    original = fence._acquire_named_mutex

    def spy(name: str, timeout_seconds: float):
        acquired.append(name)
        return original(name, timeout_seconds)

    monkeypatch.setattr(fence, "_acquire_named_mutex", spy)
    return acquired


def test_negative_admission_depth_denies_without_the_gate_and_is_not_clamped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "control"
    effect = tmp_path / "underflow-effect.txt"
    acquired = _spy_on_admission_mutex(monkeypatch)
    assert _writer_depth() == 0
    fence._WRITER_LOCAL.depth = -1
    try:
        with pytest.raises(fence.WriterFenceError) as exc_info:
            with fence.writer_admission("underflow_sink", control_root=root):
                effect.write_text("bad", encoding="utf-8")
        assert exc_info.value.code == "WRITER_ADMISSION_DEPTH_UNDERFLOW"
        assert acquired == []
        assert not effect.exists()
        assert not root.exists()
        # Fail closed, not repaired: the corrupted count survives, so every
        # later writer on this thread is denied instead of one silently
        # passing through the nested branch with no mutex.
        assert _writer_depth() == -1
        with pytest.raises(fence.WriterFenceError) as again:
            with fence.writer_admission("underflow_sink", control_root=root):
                effect.write_text("bad", encoding="utf-8")
        assert again.value.code == "WRITER_ADMISSION_DEPTH_UNDERFLOW"
        assert acquired == []
        assert not effect.exists()
    finally:
        fence._WRITER_LOCAL.depth = 0


def test_nested_admission_reuses_one_gate_and_returns_depth_to_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "control"
    acquired = _spy_on_admission_mutex(monkeypatch)
    assert _writer_depth() == 0
    with fence.writer_admission("outer_sink", control_root=root):
        assert _writer_depth() == 1
        with fence.writer_admission("inner_sink", control_root=root):
            assert _writer_depth() == 2
        assert _writer_depth() == 1
    assert _writer_depth() == 0
    assert len(acquired) == 1, "the nested writer must not take a second admission"
    with fence.writer_admission("outer_sink", control_root=root):
        assert _writer_depth() == 1
    assert _writer_depth() == 0
    assert len(acquired) == 2, "a writer after a balanced nest must take the gate again"


def test_every_derived_sink_has_negative_and_positive_admission_controls(
    tmp_path: Path,
) -> None:
    inventory = json.loads(
        (ROOT / "tools" / "container_writer_sink_inventory.json").read_text(
            encoding="utf-8"
        )
    )
    sink_rows = list(inventory["writer_sinks"])
    sink_rows.extend(
        {
            "source": row["source"],
            "function": "powershell::" + row["file"],
        }
        for row in inventory["powershell_writer_sinks"]
    )
    sources = inventory["writer_sink_sources"]
    assert sources == sorted(set(sources)) and sources
    assert sink_rows
    assert {row["source"] for row in sink_rows} == set(sources)
    root = tmp_path / "control"
    token = "s" * 48
    payload = _active_payload(token=token, sources=sources)
    active = _write_active(root, payload)
    before = (active.read_bytes(), active.stat().st_mtime_ns)
    effects: list[str] = []

    for row in sink_rows:
        source = row["source"]
        with pytest.raises(fence.WriterFencedError) as exc_info:
            with fence.writer_admission(source, control_root=root, environ={}):
                effects.append(row["function"])
        assert exc_info.value.code == "ACTIVE_WRITER_FENCE"
    assert effects == []
    assert (active.read_bytes(), active.stat().st_mtime_ns) == before

    ready = threading.Event()
    release = threading.Event()

    def hold_authority() -> None:
        lease = fence._acquire_named_mutex(payload["session_authority_mutex_name"], 1.0)
        assert lease is not None and not lease.abandoned
        ready.set()
        release.wait(10)
        lease.release()

    thread = threading.Thread(target=hold_authority, daemon=True)
    thread.start()
    assert ready.wait(5)
    environment = {
        fence.DELEGATION_TOKEN_ENV: token,
        fence.DELEGATION_SESSION_ENV: payload["session_id"],
        fence.DELEGATION_ATTEMPT_ENV: payload["attempt_id"],
        fence.DELEGATION_TRANSACTION_ENV: payload["replacement_transaction_id"],
    }
    try:
        for row in sink_rows:
            source = row["source"]
            with fence.writer_admission(
                source, control_root=root, environ=environment
            ):
                effects.append(row["function"])
    finally:
        release.set()
        thread.join(5)
    assert effects == [row["function"] for row in sink_rows]
    assert (active.read_bytes(), active.stat().st_mtime_ns) == before


def test_prepared_receipt_tamper_denies_delegated_sink_zero_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "control"
    receipt = tmp_path / "prepared.json"
    receipt.write_text('{"status":"PREPARED_DISABLED"}\n', encoding="utf-8")
    token = "p" * 48
    payload = _active_payload(token=token, sources=["delegated_sink"])
    payload["status"] = "PREPARED"
    payload["prepared_receipt_path"] = str(receipt.resolve())
    payload["prepared_receipt_sha256"] = hashlib.sha256(receipt.read_bytes()).hexdigest()
    active = _write_active(root, payload)
    receipt.write_text('{"status":"TAMPERED"}\n', encoding="utf-8")
    effect = tmp_path / "effect.txt"
    before = (active.read_bytes(), receipt.read_bytes())
    environment = {
        fence.DELEGATION_TOKEN_ENV: token,
        fence.DELEGATION_SESSION_ENV: payload["session_id"],
        fence.DELEGATION_ATTEMPT_ENV: payload["attempt_id"],
        fence.DELEGATION_TRANSACTION_ENV: payload["replacement_transaction_id"],
    }
    with pytest.raises(fence.WriterFenceError) as exc_info:
        with fence.writer_admission(
            "delegated_sink", control_root=root, environ=environment
        ):
            effect.write_text("bad", encoding="utf-8")
    assert exc_info.value.code == "FENCE_PREPARED_RECEIPT_MISMATCH"
    assert not effect.exists()
    assert (active.read_bytes(), receipt.read_bytes()) == before


@pytest.mark.skipif(not WINPS.exists(), reason="Windows PowerShell 5.1 is required")
def test_winps_helper_rejects_naive_timestamp_and_missing_release_authorization(tmp_path: Path) -> None:
    control = tmp_path / "control"
    authorization = tmp_path / "missing.json"
    prepared = tmp_path / "prepared.json"
    prepared.write_text("{}\n", encoding="utf-8")
    script = f"""
$ErrorActionPreference = 'Stop'
. '{str(PS_HELPER).replace("'", "''")}'
$naiveRejected = $false
try {{ [void](ConvertTo-ContainerWriterFenceUtc '2026-08-30T01:02:03') }} catch {{ $naiveRejected = $true }}
if (-not $naiveRejected) {{ throw 'NAIVE_TIMESTAMP_ACCEPTED' }}
$sid='0'*32; $aid='1'*32; $tx='3'*32; $orch='2'*64; $contract='4'*64
$prepared='{str(prepared).replace("'", "''")}'
$preparedSha=Get-ContainerWriterFenceFileSha256 $prepared
$authority = Enter-ContainerWriterSessionAuthority -SessionId $sid -AttemptId $aid -OrchestratorSha256 $orch -ReplacementTransactionId $tx -WriterContractSha256 $contract
[void](Start-ContainerWriterFence -ControlRoot '{str(control).replace("'", "''")}' -Status PREPARING -OwnerKind session_adapter -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -SessionStartedAtUtc '2026-08-30T01:02:03Z' -OrchestratorSha256 $orch -WriterContractSha256 $contract -PreparedReceiptPath $prepared -PreparedReceiptSha256 $preparedSha -AuthorityLease $authority)
$releaseRejected=$false
try {{ [void](Stop-ContainerWriterFence -ControlRoot '{str(control).replace("'", "''")}' -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -ReleaseAuthorizationPath '{str(authorization).replace("'", "''")}' -ReleaseAuthorizationSha256 ('a'*64) -AuthorityLease $authority) }} catch {{ $releaseRejected=$true }}
if (-not $releaseRejected) {{ throw 'MISSING_AUTHORIZATION_ACCEPTED' }}
if (-not (Test-Path -LiteralPath (Get-ContainerWriterFenceActivePath '{str(control).replace("'", "''")}' ) -PathType Leaf)) {{ throw 'ACTIVE_FENCE_WAS_CLEARED' }}
Exit-ContainerWriterSessionAuthority $authority
'PASS'
"""
    completed = subprocess.run(
        [str(WINPS), "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "PASS" in completed.stdout


@pytest.mark.skipif(not WINPS.exists(), reason="Windows PowerShell 5.1 is required")
def test_winps_helper_validates_before_write_and_resumes_exact_release(tmp_path: Path) -> None:
    control = tmp_path / "control"
    authorization = tmp_path / "prepared.json"
    authorization.write_text("{}\n", encoding="utf-8")
    script = f"""
$ErrorActionPreference = 'Stop'
. '{str(PS_HELPER).replace("'", "''")}'
$root='{str(control).replace("'", "''")}'
$authorization='{str(authorization).replace("'", "''")}'
$sid='5'*32; $aid='6'*32; $tx='7'*32; $orch='8'*64; $contract='9'*64
$authorizationSha=Get-ContainerWriterFenceFileSha256 $authorization
$authority=Enter-ContainerWriterSessionAuthority -SessionId $sid -AttemptId $aid -OrchestratorSha256 $orch -ReplacementTransactionId $tx -WriterContractSha256 $contract
try {{
  [void](Start-ContainerWriterFence -ControlRoot $root -Status PREPARING -OwnerKind session_adapter -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -SessionStartedAtUtc '2026-08-30T01:02:03Z' -OrchestratorSha256 $orch -WriterContractSha256 $contract -PreparedReceiptPath $authorization -PreparedReceiptSha256 $authorizationSha -AuthorityLease $authority)
  $activePath=Get-ContainerWriterFenceActivePath $root
  $before=Get-ContainerWriterFenceFileSha256 $activePath
  $invalidStatusRejected=$false
  try {{ [void](Set-ContainerWriterFencePrepared -ControlRoot $root -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -PreparedReceiptPath $authorization -PreparedReceiptSha256 $authorizationSha -Status WRONG -AuthorityLease $authority) }} catch {{ $invalidStatusRejected=$true }}
  if (-not $invalidStatusRejected -or (Get-ContainerWriterFenceFileSha256 $activePath) -cne $before) {{ throw 'INVALID_STATUS_MUTATED_ACTIVE' }}
  $invalidSourceRejected=$false
  try {{ [void](Set-ContainerWriterFenceDelegation -ControlRoot $root -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -DelegationToken ('d'*48) -DelegatedSources @('') -AuthorityLease $authority) }} catch {{ $invalidSourceRejected=$true }}
  if (-not $invalidSourceRejected -or (Get-ContainerWriterFenceFileSha256 $activePath) -cne $before) {{ throw 'INVALID_SOURCE_MUTATED_ACTIVE' }}
  [void](Set-ContainerWriterFencePrepared -ControlRoot $root -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -PreparedReceiptPath $authorization -PreparedReceiptSha256 $authorizationSha -AuthorityLease $authority)
  $preparedBytes=[IO.File]::ReadAllBytes($activePath)
  [void](Stop-ContainerWriterFence -ControlRoot $root -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -ReleaseAuthorizationPath $authorization -ReleaseAuthorizationSha256 $authorizationSha -AuthorityLease $authority)
  if (Test-Path -LiteralPath $activePath) {{ throw 'FIRST_RELEASE_RETAINED_ACTIVE' }}
  [IO.File]::WriteAllBytes($activePath,$preparedBytes)
  [void](Stop-ContainerWriterFence -ControlRoot $root -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -ReleaseAuthorizationPath $authorization -ReleaseAuthorizationSha256 $authorizationSha -AuthorityLease $authority)
  if (Test-Path -LiteralPath $activePath) {{ throw 'RESUMED_RELEASE_RETAINED_ACTIVE' }}
}}
finally {{ Exit-ContainerWriterSessionAuthority $authority }}
'PASS'
"""
    completed = subprocess.run(
        [str(WINPS), "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "PASS" in completed.stdout


@pytest.mark.skipif(not WINPS.exists(), reason="Windows PowerShell 5.1 is required")
def test_scheduled_task_wrappers_require_exact_fence_and_preserve_fence_bytes(
    tmp_path: Path,
) -> None:
    control = tmp_path / "control"
    authorization = tmp_path / "authorization.json"
    authorization.write_text("{}\n", encoding="utf-8")
    script = f"""
$ErrorActionPreference='Stop'
. '{str(PS_HELPER).replace("'", "''")}'
$root='{str(control).replace("'", "''")}'
$authorization='{str(authorization).replace("'", "''")}'
$sid='a'*32; $aid='b'*32; $tx='c'*32; $orch='d'*64; $contract='e'*64
$script:enabled=$true; $script:state='Ready'; $script:mutations=0
function Disable-ScheduledTask {{ param($TaskName,$TaskPath,$ErrorAction); $script:mutations++; $script:enabled=$false }}
function Enable-ScheduledTask {{ param($TaskName,$TaskPath,$ErrorAction); $script:mutations++; $script:enabled=$true }}
function Get-ScheduledTask {{ param($TaskName,$TaskPath,$ErrorAction); [pscustomobject][ordered]@{{ State=$script:state; Settings=[pscustomobject][ordered]@{{ Enabled=$script:enabled }} }} }}
$authorizationBytes=[IO.File]::ReadAllBytes($authorization)
$authorizationSha=Get-ContainerWriterFenceFileSha256 $authorization
$authority=Enter-ContainerWriterSessionAuthority -SessionId $sid -AttemptId $aid -OrchestratorSha256 $orch -ReplacementTransactionId $tx -WriterContractSha256 $contract
try {{
  $missingReceiptRejected=$false
  try {{ [void](Start-ContainerWriterFence -ControlRoot $root -Status INSTALLING -OwnerKind canonical_installer -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -SessionStartedAtUtc '2026-08-30T01:02:03Z' -OrchestratorSha256 $orch -WriterContractSha256 $contract -PreparedReceiptPath $authorization -AuthorityLease $authority) }} catch {{ $missingReceiptRejected=$true }}
  if (-not $missingReceiptRejected -or (Test-Path -LiteralPath (Get-ContainerWriterFenceActivePath $root))) {{ throw 'MISSING_PREPARED_RECEIPT_ADMITTED' }}
  [void](Start-ContainerWriterFence -ControlRoot $root -Status INSTALLING -OwnerKind canonical_installer -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -SessionStartedAtUtc '2026-08-30T01:02:03Z' -OrchestratorSha256 $orch -WriterContractSha256 $contract -PreparedReceiptPath $authorization -PreparedReceiptSha256 $authorizationSha -AuthorityLease $authority)
  $activePath=Get-ContainerWriterFenceActivePath $root
  $before=[IO.File]::ReadAllBytes($activePath)
  [IO.File]::WriteAllText($authorization,"tampered`n",(New-Object Text.UTF8Encoding($false)))
  $tamperRejected=$false
  try {{ [void](Disable-ContainerScheduledTaskUnderWriterFence -ControlRoot $root -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -AuthorityLease $authority -TaskName t -TaskPath '\') }} catch {{ $tamperRejected=$true }}
  if (-not $tamperRejected -or $script:mutations -ne 0) {{ throw 'TAMPERED_PREPARED_RECEIPT_REACHED_TASK_MUTATION' }}
  [IO.File]::WriteAllBytes($authorization,$authorizationBytes)
  $rejected=$false
  try {{ [void](Disable-ContainerScheduledTaskUnderWriterFence -ControlRoot $root -SessionId $sid -AttemptId ('f'*32) -ReplacementTransactionId $tx -AuthorityLease $authority -TaskName t -TaskPath '\') }} catch {{ $rejected=$true }}
  if (-not $rejected -or $script:mutations -ne 0) {{ throw 'INVALID_TUPLE_REACHED_TASK_MUTATION' }}
  if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$before,[byte[]][IO.File]::ReadAllBytes($activePath))) {{ throw 'DENIAL_MUTATED_FENCE' }}
  [void](Disable-ContainerScheduledTaskUnderWriterFence -ControlRoot $root -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -AuthorityLease $authority -TaskName t -TaskPath '\')
  if ($script:mutations -ne 1 -or $script:enabled) {{ throw 'VALID_DISABLE_NOT_OBSERVED' }}
  [void](Enable-ContainerScheduledTaskUnderWriterFence -ControlRoot $root -SessionId $sid -AttemptId $aid -ReplacementTransactionId $tx -AuthorityLease $authority -TaskName t -TaskPath '\')
  if ($script:mutations -ne 2 -or -not $script:enabled) {{ throw 'VALID_ENABLE_NOT_OBSERVED' }}
  if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$before,[byte[]][IO.File]::ReadAllBytes($activePath))) {{ throw 'VALID_TASK_MUTATION_CHANGED_FENCE' }}
}}
finally {{ Exit-ContainerWriterSessionAuthority $authority }}
'PASS'
"""
    completed = subprocess.run(
        [str(WINPS), "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "PASS" in completed.stdout
