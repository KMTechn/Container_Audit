"""WAL cleanup cannot discard a transaction or wait for another connection."""

import sqlite3

import pytest

import direct_sync_push
import storage_utils


@pytest.mark.parametrize("store_kind", ["seal", "exchange", "lease"])
def test_business_store_close_truncates_wal_and_preserves_committed_rows(tmp_path, store_kind):
    from transfer_store import TransferSealStore
    from transfer_member_exchange import TransferMemberExchangeStore
    from terminal_operation_lease import OperationLeaseStore

    store_type = {"seal": TransferSealStore, "exchange": TransferMemberExchangeStore, "lease": OperationLeaseStore}[store_kind]
    path = tmp_path / "business.sqlite3"
    observer = sqlite3.connect(path)
    observer.execute("PRAGMA journal_mode=WAL")
    observer.execute("CREATE TABLE state (value INTEGER)")
    observer.commit()
    observer.execute("SELECT * FROM state").fetchall()
    store = store_type.__new__(store_type)
    store.db_path = str(path)
    store._ui_thread_id_provider = lambda: -1
    try:
        with store._connect() as conn:
            conn.execute("INSERT INTO state VALUES (1)")
            conn.commit()
        assert path.with_name(path.name + "-wal").stat().st_size == 0
        assert observer.execute("SELECT * FROM state").fetchall() == [(1,)]
    finally:
        observer.close()
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()


def test_relay_close_truncates_wal_with_an_idle_observer_then_removes_sidecars(tmp_path):
    path = tmp_path / "relay.sqlite3"
    observer = sqlite3.connect(path)
    observer.execute("PRAGMA journal_mode=WAL")
    observer.execute("CREATE TABLE observer_anchor (value INTEGER)")
    observer.commit()
    observer.execute("SELECT * FROM observer_anchor").fetchall()
    try:
        direct_sync_push.init_relay_queue_schema(path)
        assert path.with_name(path.name + "-wal").stat().st_size == 0
    finally:
        observer.close()
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT count(*) FROM direct_sync_relay_batches").fetchone() == (0,)
    finally:
        conn.close()


@pytest.mark.parametrize("busy", [False, True])
def test_close_rolls_back_uncommitted_work_and_busy_checkpoint_does_not_block(tmp_path, caplog, busy):
    path = tmp_path / "state.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE state (value INTEGER)")
    conn.execute("INSERT INTO state VALUES (1)")
    conn.commit()
    observer = sqlite3.connect(path)
    try:
        if busy:
            observer.execute("BEGIN")
            observer.execute("SELECT * FROM state").fetchall()
        conn.execute("INSERT INTO state VALUES (2)")
        storage_utils.close_sqlite_connection(conn)
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")
        if busy:
            assert "busy" in caplog.text.lower()
            observer.rollback()
        assert observer.execute("SELECT * FROM state").fetchall() == [(1,)]
    finally:
        observer.close()
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()


def test_checkpoint_error_still_closes_connection(caplog):
    class Connection:
        in_transaction = False
        closed = False

        def execute(self, statement):
            if "wal_checkpoint" in statement:
                raise sqlite3.OperationalError("synthetic checkpoint failure")

        def close(self):
            self.closed = True

    conn = Connection()
    storage_utils.close_sqlite_connection(conn)
    assert conn.closed
    assert "OperationalError" in caplog.text
