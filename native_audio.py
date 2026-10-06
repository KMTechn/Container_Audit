"""Small stdlib-only WAV playback adapter for Container Audit."""

from __future__ import annotations

from pathlib import Path

try:
    import winsound as _winsound
except ImportError:  # pragma: no cover - Windows is the supported runtime.
    _winsound = None


# Complete public records contain constants only; backend details stay private.
_AUDIO_FAILURE_RECORDS = {
    "AUDIO_INIT_FAILED": 'CONTAINER_AUDIT_AUDIO={"code":"AUDIO_INIT_FAILED"}',
    "AUDIO_PLAY_FAILED": 'CONTAINER_AUDIT_AUDIO={"code":"AUDIO_PLAY_FAILED"}',
    "AUDIO_STOP_FAILED": 'CONTAINER_AUDIT_AUDIO={"code":"AUDIO_STOP_FAILED"}',
}


def record_audio_failure(code: str) -> None:
    """Record a fixed failure code without interrupting the business action."""
    try:
        print(_AUDIO_FAILURE_RECORDS[code])
    except Exception:
        # An unavailable diagnostic stream must not undo a durable operation.
        pass


class WavSound:
    """Expose the one-shot and looping WAV surface used by the application."""

    def __init__(self, path: str | Path) -> None:
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"WAV file does not exist: {resolved}")
        self.path = str(resolved)

    def play(self, loops: int = 0) -> None:
        if _winsound is None:
            raise RuntimeError("winsound is unavailable on this runtime")
        if loops not in {0, -1}:
            raise ValueError("Container audio supports one-shot or indefinite playback")
        flags = (
            _winsound.SND_FILENAME
            | _winsound.SND_ASYNC
            | getattr(_winsound, "SND_NODEFAULT", 0)
        )
        if loops == -1:
            flags |= _winsound.SND_LOOP
        _winsound.PlaySound(self.path, flags)

    def stop(self) -> None:
        stop_all_sounds()


def play_sound(sound: WavSound | None, loops: int = 0) -> bool:
    """Keep optional feedback failures outside the owner's business operation."""
    if sound is None:
        return False
    try:
        if loops == 0:
            sound.play()
        else:
            sound.play(loops=loops)
    except Exception:
        record_audio_failure("AUDIO_PLAY_FAILED")
        return False
    return True


def stop_sound(sound: WavSound | None) -> None:
    """Stop an optional sound, including injected adapters, without raising."""
    if sound is None:
        return
    try:
        sound.stop()
    except Exception:
        record_audio_failure("AUDIO_STOP_FAILED")


def stop_all_sounds() -> None:
    """Stop the process-wide asynchronous winsound channel."""

    if _winsound is None:
        record_audio_failure("AUDIO_STOP_FAILED")
        return
    try:
        _winsound.PlaySound(None, 0)
    except Exception:
        record_audio_failure("AUDIO_STOP_FAILED")


__all__ = ["WavSound", "play_sound", "stop_sound", "stop_all_sounds", "record_audio_failure"]
