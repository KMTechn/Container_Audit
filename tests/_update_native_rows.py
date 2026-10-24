"""Native lifetime witnesses for the existing simulated process census."""
import auto_update as updates


def native_row_identity(rows, pid, *, current_pid):
    if pid == current_pid:
        return {"status": "LIVE", "creation_identity": "current"}
    row = next((row for row in rows if row.get("pid") == pid), None)
    if row is None:
        return {"status": "ABSENT"}
    try:
        delta = updates._utc(row["created_at"]) - updates._utc("1601-01-01T00:00:00+00:00")
        ticks = (delta.days * 86400 + delta.seconds) * 10**7 + delta.microseconds * 10
    except (KeyError, TypeError, ValueError, OverflowError):
        return {"status": "UNKNOWN"}
    return {"status": "LIVE", "creation_identity": str(ticks)}
