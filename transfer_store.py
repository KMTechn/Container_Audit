"""Atomic local completion ledger and replayable SQLite transfer outbox."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from transfer_common import (
    SCHEMA_VERSION,
    LOCAL_COMPLETION_SCHEMA_VERSION,
    REPLACEMENT_WAITING_SCHEMA_VERSION,
    REPLACEMENT_WAITING_EVENT,
    POST_REVIEW_SCHEMA_VERSION,
    POST_REVIEW_REQUIRED_EVENT,
    PENDING_STATUSES,
    _utc_now,
    _canonical_json,
    _sha256,
    _normalize_identifier,
    normalize_barcode,
    _deterministic_id,
    TransferSealError,
    TransferCoordinatorOwnerBindingError,
    TransferCoordinatorUiThreadBindingError,
    _assert_transfer_coordinator_owner,
    _assert_not_transfer_coordinator_ui_thread,
)
from writer_session_fence import writer_sink


class TransferSealStore:
    """Atomic local completion ledger and replayable SQLite transfer outbox."""

    @writer_sink("transfer_seal")
    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        owner_thread_id_provider: Callable[[], int | None] | None = None,
        ui_thread_id_provider: Callable[[], int | None] | None = None,
    ) -> None:
        self.db_path = str(db_path)
        # Schema bootstrap is constructor-owned; every public write after
        # construction requires an explicit owner, even without a coordinator.
        self._coordinator_owner_bound = True
        self._owner_thread_id_provider = owner_thread_id_provider
        self._owner_thread_id_provider_bound = (
            owner_thread_id_provider is not None
        )
        # Schema bootstrap is the only UI-thread SQLite window.  It is closed
        # exactly once below and has no API that can reopen it.
        self._ui_thread_id_provider = None
        self._ui_thread_id_provider_bound = False
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self.bind_ui_thread_id_provider(ui_thread_id_provider)

    def bind_owner_thread_id_provider(
        self,
        owner_thread_id_provider: Callable[[], int | None] | None,
    ) -> None:
        if getattr(self, "_owner_thread_id_provider_bound", False):
            if owner_thread_id_provider is not self._owner_thread_id_provider:
                raise TransferCoordinatorOwnerBindingError()
            return
        self._owner_thread_id_provider = owner_thread_id_provider
        self._owner_thread_id_provider_bound = (
            owner_thread_id_provider is not None
        )
        self._coordinator_owner_bound = True

    def bind_ui_thread_id_provider(
        self,
        ui_thread_id_provider: Callable[[], int | None] | None,
    ) -> None:
        if getattr(self, "_ui_thread_id_provider_bound", False):
            if ui_thread_id_provider is not self._ui_thread_id_provider:
                raise TransferCoordinatorUiThreadBindingError()
            return
        self._ui_thread_id_provider = ui_thread_id_provider
        self._ui_thread_id_provider_bound = ui_thread_id_provider is not None

    def _assert_not_ui_thread_read(self) -> None:
        _assert_not_transfer_coordinator_ui_thread(
            getattr(self, "_ui_thread_id_provider", None)
        )

    def _assert_coordinator_owner(self) -> None:
        if self._coordinator_owner_bound:
            _assert_transfer_coordinator_owner(
                self._owner_thread_id_provider
            )

    @contextmanager
    def _connect(self):
        self._assert_not_ui_thread_read()
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _linked_event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
        payload = {
            "schema_version": LOCAL_COMPLETION_SCHEMA_VERSION,
            "event_type": "LINKED",
            "intent_id": str(row["intent_id"]),
            "idempotency_key": str(row["idempotency_key"]),
            "intent": {
                "schema_version": str(row["schema_version"]),
                "master_label": str(row["master_label"]),
                "source_identity": json.loads(str(row["source_identity_json"])),
                "item_id": str(row["item_id"]),
                "operator": str(row["operator"]),
                "scanned_barcodes": json.loads(str(row["scanned_barcodes_json"])),
                "scan_count": int(row["scan_count"]),
                "intent_hash": str(row["intent_hash"]),
            },
        }
        operation_lease_id = str(
            row["operation_lease_id"]
            if "operation_lease_id" in row.keys()
            else ""
        ).strip()
        if operation_lease_id:
            payload["intent"]["operation_lease_id"] = operation_lease_id
        return payload

    @classmethod
    @writer_sink("transfer_seal")
    def _ensure_linked_event(
        cls,
        conn: sqlite3.Connection,
        row: Mapping[str, Any],
    ) -> str:
        payload = cls._linked_event_payload(row)
        payload_json = _canonical_json(payload)
        payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        completion_id = _deterministic_id(
            "TRANSFER-LINKED",
            {
                "intent_id": str(row["intent_id"]),
                "idempotency_key": str(row["idempotency_key"]),
                "intent_hash": str(row["intent_hash"]),
            },
        )
        conn.execute(
            """INSERT OR IGNORE INTO transfer_completion_ledger (
                   completion_id,intent_id,event_type,idempotency_key,
                   payload_json,payload_hash,created_at
               ) VALUES (?,?,?,?,?,?,?)""",
            (
                completion_id,
                str(row["intent_id"]),
                "LINKED",
                str(row["idempotency_key"]),
                payload_json,
                payload_hash,
                str(row["created_at"]),
            ),
        )
        linked = conn.execute(
            "SELECT * FROM transfer_completion_ledger WHERE intent_id=?",
            (str(row["intent_id"]),),
        ).fetchone()
        if linked is None or (
            linked["completion_id"] != completion_id
            or linked["event_type"] != "LINKED"
            or linked["idempotency_key"] != str(row["idempotency_key"])
            or linked["payload_json"] != payload_json
            or linked["payload_hash"] != payload_hash
        ):
            raise ValueError("durable local completion differs from transfer intent")
        return completion_id

    @staticmethod
    def _load_in_connection(
        conn: sqlite3.Connection,
        intent_id: str,
    ) -> sqlite3.Row | None:
        return conn.execute(
            """SELECT intent.*, linked.completion_id AS local_completion_id
                 FROM transfer_seal_intents AS intent
                 LEFT JOIN transfer_completion_ledger AS linked
                   ON linked.intent_id=intent.intent_id
                WHERE intent.intent_id=?""",
            (intent_id,),
        ).fetchone()

    @writer_sink("transfer_seal")
    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS transfer_seal_intents (
                    intent_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'PREPARED','COMMAND_READY','RETRY_WAIT','ACKED','OPERATOR_REVIEW'
                    )),
                    master_label TEXT NOT NULL,
                    source_identity_json TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    scanned_barcodes_json TEXT NOT NULL,
                    scan_count INTEGER NOT NULL CHECK(scan_count > 0),
                    intent_hash TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    operation_lease_id TEXT NOT NULL DEFAULT '',
                    command_id TEXT UNIQUE,
                    command_json TEXT,
                    command_hash TEXT,
                    receipt_json TEXT,
                    seal_qr_payload TEXT,
                    last_error_code TEXT,
                    last_error_message TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    completion_checkpoint_confirmed INTEGER NOT NULL DEFAULT 1
                        CHECK(completion_checkpoint_confirmed IN (0,1)),
                    relay_log_file_path TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK((command_json IS NULL) = (command_id IS NULL)),
                    CHECK((command_json IS NULL) = (command_hash IS NULL))
                );
                CREATE TRIGGER IF NOT EXISTS trg_transfer_command_immutable
                BEFORE UPDATE OF command_id, command_json, command_hash
                ON transfer_seal_intents
                WHEN OLD.command_json IS NOT NULL AND (
                    NEW.command_id <> OLD.command_id OR
                    NEW.command_json <> OLD.command_json OR
                    NEW.command_hash <> OLD.command_hash
                )
                BEGIN SELECT RAISE(ABORT, 'transfer seal command is immutable'); END;
                CREATE TABLE IF NOT EXISTS transfer_exchange_block_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    reason_code TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(transfer_seal_intents)")
            }
            if "idempotency_key" not in columns:
                conn.execute(
                    "ALTER TABLE transfer_seal_intents ADD COLUMN idempotency_key TEXT"
                )
            if "relay_log_file_path" not in columns:
                conn.execute(
                    "ALTER TABLE transfer_seal_intents "
                    "ADD COLUMN relay_log_file_path TEXT NOT NULL DEFAULT ''"
                )
            if "operation_lease_id" not in columns:
                conn.execute(
                    "ALTER TABLE transfer_seal_intents "
                    "ADD COLUMN operation_lease_id TEXT NOT NULL DEFAULT ''"
                )
            if "completion_checkpoint_confirmed" not in columns:
                conn.execute(
                    "ALTER TABLE transfer_seal_intents "
                    "ADD COLUMN completion_checkpoint_confirmed "
                    "INTEGER NOT NULL DEFAULT 1"
                )
            conn.execute(
                """UPDATE transfer_seal_intents
                      SET idempotency_key='container-seal:' || intent_hash
                    WHERE idempotency_key IS NULL OR idempotency_key=''"""
            )
            mismatched = conn.execute(
                """SELECT intent_id FROM transfer_seal_intents
                    WHERE command_id IS NOT NULL
                      AND command_id <> idempotency_key
                    LIMIT 1"""
            ).fetchone()
            if mismatched is not None:
                raise sqlite3.IntegrityError(
                    "stored transfer command id differs from durable idempotency key"
                )
            conn.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS
                       ux_transfer_seal_intents_idempotency_key
                       ON transfer_seal_intents(idempotency_key)"""
            )
            conn.commit()
            conn.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS trg_transfer_idempotency_immutable
                BEFORE UPDATE OF idempotency_key
                ON transfer_seal_intents
                WHEN NEW.idempotency_key IS NOT OLD.idempotency_key
                BEGIN SELECT RAISE(ABORT, 'transfer seal idempotency key is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trg_transfer_operation_lease_immutable
                BEFORE UPDATE OF operation_lease_id
                ON transfer_seal_intents
                WHEN NEW.operation_lease_id IS NOT OLD.operation_lease_id
                BEGIN SELECT RAISE(ABORT, 'transfer operation lease binding is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trg_transfer_relay_log_path_immutable
                BEFORE UPDATE OF relay_log_file_path
                ON transfer_seal_intents
                WHEN OLD.relay_log_file_path <> ''
                 AND NEW.relay_log_file_path IS NOT OLD.relay_log_file_path
                BEGIN SELECT RAISE(ABORT, 'transfer relay log path is immutable'); END;
                CREATE TABLE IF NOT EXISTS transfer_completion_ledger (
                    ledger_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    completion_id TEXT NOT NULL UNIQUE,
                    intent_id TEXT NOT NULL UNIQUE
                        REFERENCES transfer_seal_intents(intent_id),
                    event_type TEXT NOT NULL CHECK(event_type='LINKED'),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS trg_transfer_completion_immutable_update
                BEFORE UPDATE ON transfer_completion_ledger
                BEGIN SELECT RAISE(ABORT, 'transfer completion ledger is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_transfer_completion_immutable_delete
                BEFORE DELETE ON transfer_completion_ledger
                BEGIN SELECT RAISE(ABORT, 'transfer completion ledger is append-only'); END;
                CREATE TABLE IF NOT EXISTS transfer_post_review_cases (
                    case_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    review_case_id TEXT NOT NULL UNIQUE,
                    intent_id TEXT NOT NULL UNIQUE
                        REFERENCES transfer_seal_intents(intent_id),
                    event_type TEXT NOT NULL
                        CHECK(event_type='POST_REVIEW_REQUIRED'),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    local_completion_id TEXT NOT NULL UNIQUE
                        REFERENCES transfer_completion_ledger(completion_id),
                    error_code TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    projection_log_file_path TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS trg_transfer_post_review_case_update
                BEFORE UPDATE ON transfer_post_review_cases
                BEGIN SELECT RAISE(ABORT, 'post review case is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_transfer_post_review_case_delete
                BEFORE DELETE ON transfer_post_review_cases
                BEGIN SELECT RAISE(ABORT, 'post review case is append-only'); END;
                CREATE TABLE IF NOT EXISTS transfer_post_review_outbox (
                    outbox_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    review_case_id TEXT NOT NULL UNIQUE
                        REFERENCES transfer_post_review_cases(review_case_id),
                    event_type TEXT NOT NULL
                        CHECK(event_type='POST_REVIEW_REQUIRED'),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    projection_log_file_path TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS trg_transfer_post_review_outbox_update
                BEFORE UPDATE ON transfer_post_review_outbox
                BEGIN SELECT RAISE(ABORT, 'post review outbox is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_transfer_post_review_outbox_delete
                BEFORE DELETE ON transfer_post_review_outbox
                BEGIN SELECT RAISE(ABORT, 'post review outbox is append-only'); END;
                CREATE TABLE IF NOT EXISTS transfer_post_review_projection_receipts (
                    projection_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    projection_id TEXT NOT NULL UNIQUE,
                    review_case_id TEXT NOT NULL UNIQUE
                        REFERENCES transfer_post_review_outbox(review_case_id),
                    event_type TEXT NOT NULL
                        CHECK(event_type='POST_REVIEW_REQUIRED'),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_hash TEXT NOT NULL,
                    projection_log_file_path TEXT NOT NULL,
                    projected_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS trg_transfer_post_review_projection_update
                BEFORE UPDATE ON transfer_post_review_projection_receipts
                BEGIN SELECT RAISE(ABORT, 'post review projection receipt is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_transfer_post_review_projection_delete
                BEFORE DELETE ON transfer_post_review_projection_receipts
                BEGIN SELECT RAISE(ABORT, 'post review projection receipt is append-only'); END;
                CREATE TABLE IF NOT EXISTS phs_replacement_waiting_ledger (
                    ledger_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    intent_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL
                        CHECK(event_type='PHS_REPLACEMENT_WAITING_MARKED'),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    session_id TEXT NOT NULL,
                    old_label_id TEXT NOT NULL,
                    old_label_hash TEXT NOT NULL,
                    new_label_id TEXT NOT NULL,
                    new_label_hash TEXT NOT NULL,
                    process_context TEXT NOT NULL,
                    location_codes_json TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    master_label TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(session_id,old_label_hash,new_label_hash)
                );
                CREATE TRIGGER IF NOT EXISTS trg_phs_replacement_waiting_ledger_update
                BEFORE UPDATE ON phs_replacement_waiting_ledger
                BEGIN SELECT RAISE(ABORT, 'replacement waiting ledger is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_phs_replacement_waiting_ledger_delete
                BEFORE DELETE ON phs_replacement_waiting_ledger
                BEGIN SELECT RAISE(ABORT, 'replacement waiting ledger is append-only'); END;
                CREATE TABLE IF NOT EXISTS phs_replacement_waiting_outbox (
                    outbox_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    intent_id TEXT NOT NULL UNIQUE
                        REFERENCES phs_replacement_waiting_ledger(intent_id),
                    event_type TEXT NOT NULL
                        CHECK(event_type='PHS_REPLACEMENT_WAITING_MARKED'),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    projection_log_file_path TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS trg_phs_replacement_waiting_outbox_update
                BEFORE UPDATE ON phs_replacement_waiting_outbox
                BEGIN SELECT RAISE(ABORT, 'replacement waiting outbox is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_phs_replacement_waiting_outbox_delete
                BEFORE DELETE ON phs_replacement_waiting_outbox
                BEGIN SELECT RAISE(ABORT, 'replacement waiting outbox is append-only'); END;
                CREATE TABLE IF NOT EXISTS phs_replacement_waiting_projection_receipts (
                    projection_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    projection_id TEXT NOT NULL UNIQUE,
                    intent_id TEXT NOT NULL UNIQUE
                        REFERENCES phs_replacement_waiting_outbox(intent_id),
                    event_type TEXT NOT NULL
                        CHECK(event_type='PHS_REPLACEMENT_WAITING_MARKED'),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_hash TEXT NOT NULL,
                    projection_log_file_path TEXT NOT NULL,
                    projected_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS trg_phs_replacement_projection_update
                BEFORE UPDATE ON phs_replacement_waiting_projection_receipts
                BEGIN SELECT RAISE(ABORT, 'replacement waiting projection receipt is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS trg_phs_replacement_projection_delete
                BEFORE DELETE ON phs_replacement_waiting_projection_receipts
                BEGIN SELECT RAISE(ABORT, 'replacement waiting projection receipt is append-only'); END;
                """
            )
            replacement_outbox_columns = {
                str(row["name"])
                for row in conn.execute(
                    "PRAGMA table_info(phs_replacement_waiting_outbox)"
                )
            }
            if "projection_log_file_path" not in replacement_outbox_columns:
                conn.execute(
                    "ALTER TABLE phs_replacement_waiting_outbox "
                    "ADD COLUMN projection_log_file_path TEXT"
                )
            conn.execute("BEGIN IMMEDIATE")
            for row in conn.execute(
                "SELECT * FROM transfer_seal_intents ORDER BY created_at, rowid"
            ).fetchall():
                self._ensure_linked_event(conn, row)
            conn.commit()

    def preview_intent(
        self,
        *,
        master_label: str,
        source_identity: Mapping[str, Any],
        item_id: str,
        scanned_barcodes: Iterable[str],
        operation_lease_id: str = "",
    ) -> dict[str, Any]:
        self._assert_not_ui_thread_read()
        raw_barcodes = [_normalize_identifier(value, "scanned_barcode") for value in scanned_barcodes]
        normalized = [normalize_barcode(value) for value in raw_barcodes]
        if not raw_barcodes or len(set(normalized)) != len(normalized):
            raise ValueError("scanned barcodes must be non-empty and unique")
        intent_material = {
            "master_label": _normalize_identifier(master_label, "master_label"),
            "source_identity": {key: str(value or "").strip() for key, value in source_identity.items()},
            "item_id": _normalize_identifier(item_id, "item_id"),
            "scanned_barcodes": raw_barcodes,
        }
        normalized_operation_lease_id = str(operation_lease_id or "").strip()
        if normalized_operation_lease_id:
            intent_material["operation_lease_id"] = _normalize_identifier(
                normalized_operation_lease_id,
                "operation_lease_id",
            )
        digest = _sha256(intent_material)
        intent_id = f"transfer-intent-{digest[:32]}"
        idempotency_key = f"container-seal:{digest}"
        return {
            "intent_material": intent_material,
            "raw_barcodes": raw_barcodes,
            "operation_lease_id": normalized_operation_lease_id,
            "intent_hash": digest,
            "intent_id": intent_id,
            "idempotency_key": idempotency_key,
        }

    @writer_sink("transfer_seal")
    def prepare(
        self,
        *,
        master_label: str,
        source_identity: Mapping[str, Any],
        item_id: str,
        operator: str,
        scanned_barcodes: Iterable[str],
        relay_log_file_path: str = "",
        operation_lease_id: str = "",
        require_completion_checkpoint: bool = False,
    ) -> sqlite3.Row:
        self._assert_coordinator_owner()
        preview = self.preview_intent(
            master_label=master_label,
            source_identity=source_identity,
            item_id=item_id,
            scanned_barcodes=scanned_barcodes,
            operation_lease_id=operation_lease_id,
        )
        intent_material = preview["intent_material"]
        raw_barcodes = preview["raw_barcodes"]
        normalized_operation_lease_id = preview["operation_lease_id"]
        digest = preview["intent_hash"]
        intent_id = preview["intent_id"]
        idempotency_key = preview["idempotency_key"]
        completion_checkpoint_confirmed = (
            0 if bool(require_completion_checkpoint) else 1
        )
        normalized_relay_log_path = (
            os.path.abspath(str(relay_log_file_path).strip())
            if str(relay_log_file_path or "").strip()
            else ""
        )
        now = _utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT OR IGNORE INTO transfer_seal_intents (
                       intent_id,schema_version,status,master_label,source_identity_json,
                       item_id,operator,scanned_barcodes_json,scan_count,intent_hash,
                       idempotency_key,operation_lease_id,relay_log_file_path,
                       completion_checkpoint_confirmed,created_at,updated_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    intent_id,
                    SCHEMA_VERSION,
                    "PREPARED",
                    intent_material["master_label"],
                    _canonical_json(intent_material["source_identity"]),
                    intent_material["item_id"],
                    str(operator or "").strip(),
                    _canonical_json(raw_barcodes),
                    len(raw_barcodes),
                    digest,
                    idempotency_key,
                    normalized_operation_lease_id,
                    normalized_relay_log_path,
                    completion_checkpoint_confirmed,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None or (
                row["intent_hash"] != digest
                or row["idempotency_key"] != idempotency_key
                or str(row["operation_lease_id"] or "")
                != normalized_operation_lease_id
            ):
                raise ValueError("durable transfer intent identity collision")
            if not str(row["relay_log_file_path"] or "") and normalized_relay_log_path:
                conn.execute(
                    "UPDATE transfer_seal_intents SET relay_log_file_path=? "
                    "WHERE intent_id=? AND relay_log_file_path=''",
                    (normalized_relay_log_path, intent_id),
                )
                row = conn.execute(
                    "SELECT * FROM transfer_seal_intents WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()
                assert row is not None
            self._ensure_linked_event(conn, row)
            row = self._load_in_connection(conn, intent_id)
            conn.commit()
        assert row is not None
        return row

    def load(self, intent_id: str) -> sqlite3.Row:
        self._assert_not_ui_thread_read()
        with self._connect() as conn:
            row = self._load_in_connection(conn, intent_id)
        if row is None:
            raise KeyError(intent_id)
        return row

    def precommand_operator_review(
        self,
        *,
        master_label: str,
        scanned_barcodes: Iterable[str],
        error_code: str,
    ) -> sqlite3.Row | None:
        """Return one exact review row only when no central command was durable."""

        self._assert_not_ui_thread_read()
        raw_barcodes = [
            _normalize_identifier(value, "scanned_barcode")
            for value in scanned_barcodes
        ]
        if not raw_barcodes:
            return None
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT *
                     FROM transfer_seal_intents
                    WHERE status='OPERATOR_REVIEW'
                      AND master_label=?
                      AND scanned_barcodes_json=?
                      AND last_error_code=?
                      AND command_id IS NULL
                      AND command_json IS NULL
                      AND receipt_json IS NULL
                    ORDER BY updated_at DESC
                    LIMIT 2""",
                (
                    _normalize_identifier(master_label, "master_label"),
                    _canonical_json(raw_barcodes),
                    _normalize_identifier(error_code, "error_code"),
                ),
            ).fetchall()
        return rows[0] if len(rows) == 1 else None

    @writer_sink("transfer_seal")
    def bind_command(self, intent_id: str, context: Mapping[str, Any]) -> sqlite3.Row:
        self._assert_coordinator_owner()
        command_id = _normalize_identifier(context.get("idempotency_key"), "idempotency_key")
        command_json = _canonical_json(dict(context))
        command_hash = hashlib.sha256(command_json.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            if not bool(row["completion_checkpoint_confirmed"]):
                raise ValueError(
                    "completion checkpoint must be confirmed before command binding"
                )
            if row["idempotency_key"] != command_id:
                raise ValueError(
                    "server command id differs from durable transfer idempotency key"
                )
            if row["command_json"] is not None:
                if (
                    row["command_id"] != command_id
                    or row["command_json"] != command_json
                    or row["command_hash"] != command_hash
                ):
                    raise ValueError("durable transfer command differs from retry payload")
            else:
                conn.execute(
                    """UPDATE transfer_seal_intents
                          SET status='COMMAND_READY',command_id=?,command_json=?,command_hash=?,
                              last_error_code=NULL,last_error_message=NULL,updated_at=?
                        WHERE intent_id=?""",
                    (command_id, command_json, command_hash, _utc_now(), intent_id),
                )
            row = self._load_in_connection(conn, intent_id)
            conn.commit()
        assert row is not None
        return row

    @writer_sink("transfer_seal")
    def confirm_completion_checkpoint(self, intent_id: str) -> sqlite3.Row:
        """Make one GUI completion intent eligible for command/HTTP dispatch."""

        self._assert_coordinator_owner()
        normalized_intent = _normalize_identifier(intent_id, "intent_id")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._load_in_connection(conn, normalized_intent)
            if row is None:
                raise KeyError(normalized_intent)
            if not bool(row["completion_checkpoint_confirmed"]):
                if row["status"] != "PREPARED":
                    raise ValueError(
                        "unconfirmed completion checkpoint is no longer PREPARED"
                    )
                conn.execute(
                    """UPDATE transfer_seal_intents
                          SET completion_checkpoint_confirmed=1,updated_at=?
                        WHERE intent_id=? AND completion_checkpoint_confirmed=0""",
                    (_utc_now(), normalized_intent),
                )
                row = self._load_in_connection(conn, normalized_intent)
                assert row is not None
            conn.commit()
        return row

    @staticmethod
    @writer_sink("transfer_seal")
    def _ensure_post_review_case(
        conn: sqlite3.Connection,
        row: Mapping[str, Any],
        error: TransferSealError,
    ) -> sqlite3.Row:
        intent_id = str(row["intent_id"])
        existing = conn.execute(
            "SELECT * FROM transfer_post_review_cases WHERE intent_id=?",
            (intent_id,),
        ).fetchone()
        if existing is not None:
            outbox = conn.execute(
                "SELECT * FROM transfer_post_review_outbox WHERE review_case_id=?",
                (str(existing["review_case_id"]),),
            ).fetchone()
            if outbox is None or (
                outbox["event_type"] != POST_REVIEW_REQUIRED_EVENT
                or outbox["idempotency_key"] != existing["idempotency_key"]
                or outbox["payload_json"] != existing["evidence_json"]
                or outbox["payload_hash"] != existing["evidence_hash"]
            ):
                raise ValueError("durable post review outbox differs from case")
            return existing

        local_completion_id = str(row["local_completion_id"] or "").strip()
        if not local_completion_id:
            raise ValueError("post review case requires durable local completion")
        transfer_idempotency_key = str(row["idempotency_key"])
        idempotency_key = "post-review:" + hashlib.sha256(
            transfer_idempotency_key.encode("utf-8")
        ).hexdigest()
        review_case_id = _deterministic_id(
            "POST-REVIEW",
            {
                "intent_id": intent_id,
                "local_completion_id": local_completion_id,
                "idempotency_key": idempotency_key,
            },
        )
        now = _utc_now()
        evidence = {
            "schema_version": POST_REVIEW_SCHEMA_VERSION,
            "event_type": POST_REVIEW_REQUIRED_EVENT,
            "review_case_id": review_case_id,
            "idempotency_key": idempotency_key,
            "transfer_intent_id": intent_id,
            "transfer_idempotency_key": transfer_idempotency_key,
            "local_completion_id": local_completion_id,
            "transfer_status": "OPERATOR_REVIEW",
            "error_code": str(error.code or "").strip(),
            "error_message": str(error),
            "status_code": int(error.status_code or 0),
            "operator": str(row["operator"] or ""),
            "master_label": str(row["master_label"] or ""),
            "created_at": now,
        }
        evidence_json = _canonical_json(evidence)
        evidence_hash = hashlib.sha256(
            evidence_json.encode("utf-8")
        ).hexdigest()
        projection_log_file_path = str(row["relay_log_file_path"] or "")
        conn.execute(
            """INSERT INTO transfer_post_review_cases (
                   review_case_id,intent_id,event_type,idempotency_key,
                   local_completion_id,error_code,evidence_json,evidence_hash,
                   projection_log_file_path,created_at
               ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                review_case_id,
                intent_id,
                POST_REVIEW_REQUIRED_EVENT,
                idempotency_key,
                local_completion_id,
                str(error.code or "").strip(),
                evidence_json,
                evidence_hash,
                projection_log_file_path,
                now,
            ),
        )
        conn.execute(
            """INSERT INTO transfer_post_review_outbox (
                   review_case_id,event_type,idempotency_key,payload_json,
                   payload_hash,projection_log_file_path,created_at
               ) VALUES (?,?,?,?,?,?,?)""",
            (
                review_case_id,
                POST_REVIEW_REQUIRED_EVENT,
                idempotency_key,
                evidence_json,
                evidence_hash,
                projection_log_file_path,
                now,
            ),
        )
        created = conn.execute(
            "SELECT * FROM transfer_post_review_cases WHERE review_case_id=?",
            (review_case_id,),
        ).fetchone()
        if created is None:
            raise ValueError("durable post review case was not created")
        return created

    @writer_sink("transfer_seal")
    def record_error(self, intent_id: str, error: TransferSealError) -> sqlite3.Row:
        self._assert_coordinator_owner()
        operator_review_codes = {
            "AMBIGUOUS_BUNDLE",
            "SOURCE_IDENTITY_MISMATCH",
            "BUNDLE_IDENTITY_MISMATCH",
            "MEMBERSHIP_CONFLICT",
            "BARCODE_NOT_IN_SOURCE_BUNDLE",
            "BARCODE_MAPPING_AMBIGUOUS",
            "PARTIAL_PHS_TRANSFER_FORBIDDEN",
            "STALE_VERSION",
            "RECEIPT_MEMBERSHIP_MISMATCH",
            "SOURCE_IDENTITY_REQUIRED",
            "AUTHORITY_INVALID",
            "AUTHORITY_PROFILE_MISMATCH",
            "RESOLVER_CONTRACT_INVALID",
            "TRANSFER_COMMAND_INTEGRITY_MISMATCH",
            "LOGISTICS_REDIRECT_BLOCKED",
        }
        terminal_cas_conflict = error.status_code in {409, 412}
        terminal_client_error = (
            400 <= error.status_code < 500
            and error.status_code != 404
            and not error.retryable
        )
        local_contract_error = (
            error.code.upper().startswith("PHS2_")
            and not error.retryable
        )
        operation_lease_contract_error = (
            error.code.upper().startswith("OPERATION_LEASE_")
            and not error.retryable
        )
        status = (
            "OPERATOR_REVIEW"
            if (
                error.code.upper() in operator_review_codes
                or terminal_cas_conflict
                or terminal_client_error
                or local_contract_error
                or operation_lease_contract_error
            )
            else "RETRY_WAIT"
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = self._load_in_connection(conn, intent_id)
            if previous is not None and previous["status"] == "OPERATOR_REVIEW":
                # A failed explicit review retry never enables automatic retry.
                status = "OPERATOR_REVIEW"
            conn.execute(
                """UPDATE transfer_seal_intents
                      SET status=?,last_error_code=?,last_error_message=?,attempt_count=attempt_count+1,
                          updated_at=? WHERE intent_id=?""",
                (status, error.code, str(error), _utc_now(), intent_id),
            )
            row = self._load_in_connection(conn, intent_id)
            if row is None:
                raise KeyError(intent_id)
            if status == "OPERATOR_REVIEW":
                self._ensure_post_review_case(conn, row, error)
            conn.commit()
        return row

    @writer_sink("transfer_seal")
    def record_receipt(self, intent_id: str, receipt: Mapping[str, Any], seal_qr_payload: str) -> sqlite3.Row:
        self._assert_coordinator_owner()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE transfer_seal_intents
                      SET status='ACKED',receipt_json=?,seal_qr_payload=?,last_error_code=NULL,
                          last_error_message=NULL,attempt_count=attempt_count+1,updated_at=?
                    WHERE intent_id=?""",
                (_canonical_json(dict(receipt)), seal_qr_payload, _utc_now(), intent_id),
            )
            row = self._load_in_connection(conn, intent_id)
            conn.commit()
        assert row is not None
        return row

    def pending_ids(self) -> list[str]:
        self._assert_not_ui_thread_read()
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT intent_id FROM transfer_seal_intents
                    WHERE status IN (?,?,?)
                      AND completion_checkpoint_confirmed=1
                    ORDER BY created_at, rowid""",
                PENDING_STATUSES,
            ).fetchall()
        return [str(row["intent_id"]) for row in rows]

    def post_review_case_for_intent(self, intent_id: str) -> sqlite3.Row:
        self._assert_not_ui_thread_read()
        normalized_intent = _normalize_identifier(intent_id, "intent_id")
        with self._connect() as conn:
            row = conn.execute(
                """SELECT review.*, outbox.outbox_sequence,
                          outbox.payload_json AS outbox_payload_json,
                          outbox.payload_hash AS outbox_payload_hash
                     FROM transfer_post_review_cases AS review
                     JOIN transfer_post_review_outbox AS outbox
                       ON outbox.review_case_id=review.review_case_id
                    WHERE review.intent_id=?""",
                (normalized_intent,),
            ).fetchone()
        if row is None:
            raise KeyError(normalized_intent)
        return row

    def post_review_cases(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        self._assert_not_ui_thread_read()
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT review.*, outbox.outbox_sequence,
                          intent.status AS intent_status, intent.item_id,
                          intent.operator, intent.scan_count,
                          (intent.command_json IS NOT NULL) AS command_bound,
                          outbox.payload_json AS outbox_payload_json,
                          outbox.payload_hash AS outbox_payload_hash
                     FROM transfer_post_review_cases AS review
                     JOIN transfer_post_review_outbox AS outbox
                       ON outbox.review_case_id=review.review_case_id
                     JOIN transfer_seal_intents AS intent
                       ON intent.intent_id=review.intent_id
                    WHERE (?=0 OR intent.status='OPERATOR_REVIEW')
                    ORDER BY outbox.outbox_sequence""",
                (int(active_only),),
            ).fetchall()
        return list(rows)

    def pending_post_review_projections(self) -> list[sqlite3.Row]:
        self._assert_not_ui_thread_read()
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT review.*, outbox.outbox_sequence,
                          outbox.payload_json AS outbox_payload_json,
                          outbox.payload_hash AS outbox_payload_hash
                     FROM transfer_post_review_cases AS review
                     JOIN transfer_post_review_outbox AS outbox
                       ON outbox.review_case_id=review.review_case_id
                     LEFT JOIN transfer_post_review_projection_receipts AS receipt
                       ON receipt.review_case_id=review.review_case_id
                    WHERE receipt.review_case_id IS NULL
                      AND outbox.projection_log_file_path <> ''
                    ORDER BY outbox.outbox_sequence"""
            ).fetchall()
        return list(rows)

    @writer_sink("transfer_seal")
    def record_post_review_projection(
        self,
        review_case_id: str,
        *,
        projection_log_file_path: str,
    ) -> sqlite3.Row:
        self._assert_coordinator_owner()
        normalized_case_id = _normalize_identifier(
            review_case_id,
            "review_case_id",
        )
        normalized_projection_path = os.path.abspath(
            _normalize_identifier(
                projection_log_file_path,
                "projection_log_file_path",
            )
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            source = conn.execute(
                """SELECT review.*, outbox.payload_hash AS outbox_payload_hash,
                          outbox.projection_log_file_path AS outbox_projection_path
                     FROM transfer_post_review_cases AS review
                     JOIN transfer_post_review_outbox AS outbox
                       ON outbox.review_case_id=review.review_case_id
                    WHERE review.review_case_id=?""",
                (normalized_case_id,),
            ).fetchone()
            if source is None:
                raise KeyError(normalized_case_id)
            if (
                str(source["outbox_projection_path"] or "")
                != normalized_projection_path
                or source["outbox_payload_hash"] != source["evidence_hash"]
            ):
                raise ValueError(
                    "post review projection differs from durable outbox"
                )
            projection_id = _deterministic_id(
                "POST-REVIEW-PROJECTION",
                {
                    "review_case_id": normalized_case_id,
                    "idempotency_key": str(source["idempotency_key"]),
                    "payload_hash": str(source["evidence_hash"]),
                },
            )
            conn.execute(
                """INSERT OR IGNORE INTO transfer_post_review_projection_receipts (
                       projection_id,review_case_id,event_type,idempotency_key,
                       payload_hash,projection_log_file_path,projected_at
                   ) VALUES (?,?,?,?,?,?,?)""",
                (
                    projection_id,
                    normalized_case_id,
                    POST_REVIEW_REQUIRED_EVENT,
                    str(source["idempotency_key"]),
                    str(source["evidence_hash"]),
                    normalized_projection_path,
                    _utc_now(),
                ),
            )
            receipt = conn.execute(
                """SELECT * FROM transfer_post_review_projection_receipts
                    WHERE review_case_id=?""",
                (normalized_case_id,),
            ).fetchone()
            if receipt is None or (
                receipt["projection_id"] != projection_id
                or receipt["event_type"] != POST_REVIEW_REQUIRED_EVENT
                or receipt["idempotency_key"] != source["idempotency_key"]
                or receipt["payload_hash"] != source["evidence_hash"]
                or receipt["projection_log_file_path"]
                != normalized_projection_path
            ):
                raise ValueError("post review projection receipt identity collision")
            conn.commit()
        return receipt

    def has_exact_history(self) -> bool:
        self._assert_not_ui_thread_read()
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM transfer_seal_intents LIMIT 1").fetchone()
        return row is not None

    @writer_sink("transfer_seal")
    def mark_phs_replacement_waiting(
        self,
        *,
        session_id: str,
        old_label_id: str,
        new_label_id: str,
        process_context: str,
        location_codes: Iterable[str],
        operator: str,
        master_label: str,
        projection_log_file_path: str,
    ) -> sqlite3.Row:
        """Atomically append one replacement-waiting fact and replay record."""

        self._assert_coordinator_owner()
        normalized_session = _normalize_identifier(session_id, "session_id")
        normalized_old = _normalize_identifier(old_label_id, "old_label_id")
        normalized_new = _normalize_identifier(new_label_id, "new_label_id")
        if normalized_old == normalized_new:
            raise ValueError("replacement labels must differ")
        normalized_process = _normalize_identifier(
            process_context,
            "process_context",
        ).lower()
        if isinstance(location_codes, (str, bytes)):
            raise ValueError("location_codes must be an iterable of identifiers")
        normalized_locations = sorted(
            {
                _normalize_identifier(value, "location_code")
                for value in location_codes
            }
        )
        if not normalized_locations:
            raise ValueError("location_codes must be non-empty")
        normalized_projection_path = os.path.abspath(
            _normalize_identifier(
                projection_log_file_path,
                "projection_log_file_path",
            )
        )
        old_hash = hashlib.sha256(normalized_old.encode("utf-8")).hexdigest()
        new_hash = hashlib.sha256(normalized_new.encode("utf-8")).hexdigest()
        idempotency_key = (
            f"replacement-wait:{normalized_session}:{old_hash}:{new_hash}"
        )
        intent_id = (
            "phs-replacement-wait-"
            + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:32]
        )
        now = _utc_now()
        evidence = {
            "schema_version": REPLACEMENT_WAITING_SCHEMA_VERSION,
            "event_type": REPLACEMENT_WAITING_EVENT,
            "intent_id": intent_id,
            "idempotency_key": idempotency_key,
            "session_id": normalized_session,
            "old_label_id": normalized_old,
            "old_label_hash": old_hash,
            "new_label_id": normalized_new,
            "new_label_hash": new_hash,
            "process_context": normalized_process,
            "location_codes": normalized_locations,
            "operator": str(operator or "").strip(),
            "master_label": str(master_label or "").strip(),
            "observed_at": now,
        }
        evidence_json = _canonical_json(evidence)
        evidence_hash = hashlib.sha256(
            evidence_json.encode("utf-8")
        ).hexdigest()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT OR IGNORE INTO phs_replacement_waiting_ledger (
                       intent_id,event_type,idempotency_key,session_id,
                       old_label_id,old_label_hash,new_label_id,new_label_hash,
                       process_context,location_codes_json,operator,master_label,
                       evidence_json,evidence_hash,created_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    intent_id,
                    REPLACEMENT_WAITING_EVENT,
                    idempotency_key,
                    normalized_session,
                    normalized_old,
                    old_hash,
                    normalized_new,
                    new_hash,
                    normalized_process,
                    _canonical_json(normalized_locations),
                    str(operator or "").strip(),
                    str(master_label or "").strip(),
                    evidence_json,
                    evidence_hash,
                    now,
                ),
            )
            ledger = conn.execute(
                """SELECT * FROM phs_replacement_waiting_ledger
                    WHERE idempotency_key=?""",
                (idempotency_key,),
            ).fetchone()
            if ledger is None or (
                ledger["intent_id"] != intent_id
                or ledger["event_type"] != REPLACEMENT_WAITING_EVENT
                or ledger["session_id"] != normalized_session
                or ledger["old_label_hash"] != old_hash
                or ledger["new_label_hash"] != new_hash
            ):
                raise ValueError(
                    "durable replacement waiting identity collision"
                )
            conn.execute(
                """INSERT OR IGNORE INTO phs_replacement_waiting_outbox (
                       intent_id,event_type,idempotency_key,payload_json,
                       payload_hash,projection_log_file_path,created_at
                   ) VALUES (?,?,?,?,?,?,?)""",
                (
                    ledger["intent_id"],
                    ledger["event_type"],
                    ledger["idempotency_key"],
                    ledger["evidence_json"],
                    ledger["evidence_hash"],
                    normalized_projection_path,
                    ledger["created_at"],
                ),
            )
            outbox = conn.execute(
                """SELECT * FROM phs_replacement_waiting_outbox
                    WHERE intent_id=?""",
                (intent_id,),
            ).fetchone()
            if outbox is None or (
                outbox["event_type"] != REPLACEMENT_WAITING_EVENT
                or outbox["idempotency_key"] != idempotency_key
                or outbox["payload_json"] != ledger["evidence_json"]
                or outbox["payload_hash"] != ledger["evidence_hash"]
                or not str(outbox["projection_log_file_path"] or "").strip()
            ):
                raise ValueError(
                    "durable replacement waiting outbox differs from ledger"
                )
            row = conn.execute(
                """SELECT ledger.*, outbox.outbox_sequence,
                          outbox.projection_log_file_path
                     FROM phs_replacement_waiting_ledger AS ledger
                     JOIN phs_replacement_waiting_outbox AS outbox
                       ON outbox.intent_id=ledger.intent_id
                    WHERE ledger.intent_id=?""",
                (intent_id,),
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def replacement_waiting_outbox(self) -> list[sqlite3.Row]:
        """Return immutable replacement-waiting replay evidence in FIFO order."""

        self._assert_not_ui_thread_read()
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ledger.*, outbox.outbox_sequence,
                          outbox.payload_json AS outbox_payload_json,
                          outbox.payload_hash AS outbox_payload_hash,
                          outbox.projection_log_file_path
                     FROM phs_replacement_waiting_outbox AS outbox
                     JOIN phs_replacement_waiting_ledger AS ledger
                       ON ledger.intent_id=outbox.intent_id
                    ORDER BY outbox.outbox_sequence"""
            ).fetchall()
        return list(rows)

    def pending_replacement_waiting_projections(self) -> list[sqlite3.Row]:
        """Return FIFO marker rows that still need their append-only CSV receipt."""

        self._assert_not_ui_thread_read()
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ledger.*, outbox.outbox_sequence,
                          outbox.payload_json AS outbox_payload_json,
                          outbox.payload_hash AS outbox_payload_hash,
                          outbox.projection_log_file_path
                     FROM phs_replacement_waiting_outbox AS outbox
                     JOIN phs_replacement_waiting_ledger AS ledger
                       ON ledger.intent_id=outbox.intent_id
                     LEFT JOIN phs_replacement_waiting_projection_receipts AS receipt
                       ON receipt.intent_id=outbox.intent_id
                    WHERE receipt.intent_id IS NULL
                      AND outbox.projection_log_file_path IS NOT NULL
                      AND outbox.projection_log_file_path <> ''
                    ORDER BY outbox.outbox_sequence"""
            ).fetchall()
        return list(rows)

    @writer_sink("transfer_seal")
    def record_replacement_waiting_projection(
        self,
        intent_id: str,
        *,
        projection_log_file_path: str,
    ) -> sqlite3.Row:
        """Append one immutable receipt after the idempotent CSV projection."""

        self._assert_coordinator_owner()
        normalized_intent = _normalize_identifier(intent_id, "intent_id")
        normalized_projection_path = os.path.abspath(
            _normalize_identifier(
                projection_log_file_path,
                "projection_log_file_path",
            )
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            source = conn.execute(
                """SELECT ledger.*, outbox.payload_hash AS outbox_payload_hash,
                          outbox.projection_log_file_path
                     FROM phs_replacement_waiting_ledger AS ledger
                     JOIN phs_replacement_waiting_outbox AS outbox
                       ON outbox.intent_id=ledger.intent_id
                    WHERE ledger.intent_id=?""",
                (normalized_intent,),
            ).fetchone()
            if source is None:
                raise KeyError(normalized_intent)
            if (
                str(source["projection_log_file_path"] or "")
                != normalized_projection_path
                or source["outbox_payload_hash"] != source["evidence_hash"]
            ):
                raise ValueError(
                    "replacement waiting projection differs from durable outbox"
                )
            projection_id = _deterministic_id(
                "PHS-WAIT-PROJECTION",
                {
                    "intent_id": normalized_intent,
                    "idempotency_key": str(source["idempotency_key"]),
                    "payload_hash": str(source["evidence_hash"]),
                },
            )
            conn.execute(
                """INSERT OR IGNORE INTO phs_replacement_waiting_projection_receipts (
                       projection_id,intent_id,event_type,idempotency_key,
                       payload_hash,projection_log_file_path,projected_at
                   ) VALUES (?,?,?,?,?,?,?)""",
                (
                    projection_id,
                    normalized_intent,
                    REPLACEMENT_WAITING_EVENT,
                    str(source["idempotency_key"]),
                    str(source["evidence_hash"]),
                    normalized_projection_path,
                    _utc_now(),
                ),
            )
            receipt = conn.execute(
                """SELECT *
                     FROM phs_replacement_waiting_projection_receipts
                    WHERE intent_id=?""",
                (normalized_intent,),
            ).fetchone()
            if receipt is None or (
                receipt["projection_id"] != projection_id
                or receipt["event_type"] != REPLACEMENT_WAITING_EVENT
                or receipt["idempotency_key"] != source["idempotency_key"]
                or receipt["payload_hash"] != source["evidence_hash"]
                or receipt["projection_log_file_path"]
                != normalized_projection_path
            ):
                raise ValueError(
                    "replacement waiting projection receipt identity collision"
                )
            conn.commit()
        return receipt

    @writer_sink("transfer_seal")
    def record_exchange_block(self, *, reason_code: str, details: Mapping[str, Any]) -> str:
        self._assert_coordinator_owner()
        created_at = _utc_now()
        material = {
            "reason_code": _normalize_identifier(reason_code, "reason_code"),
            "details": dict(details or {}),
            "created_at": created_at,
        }
        receipt_id = _deterministic_id("EXCHANGE-BLOCK", material)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO transfer_exchange_block_receipts (
                       receipt_id,reason_code,details_json,created_at
                   ) VALUES (?,?,?,?)""",
                (receipt_id, material["reason_code"], _canonical_json(material["details"]), created_at),
            )
            conn.commit()
        return receipt_id
