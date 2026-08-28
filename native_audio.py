"""Small stdlib-only WAV playback adapter for Container Audit."""

from __future__ import annotations

from pathlib import Path

try:
    import winsound as _winsound
except ImportError:  # pragma: no cover - Windows is the supported runtime.
    _winsound = None


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


def stop_all_sounds() -> None:
    """Stop the process-wide asynchronous winsound channel."""

    if _winsound is not None:
        _winsound.PlaySound(None, 0)


__all__ = ["WavSound", "stop_all_sounds"]
