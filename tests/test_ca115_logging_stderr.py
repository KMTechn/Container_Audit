"""Exercise lastResort without a configured logging handler in-process."""
from contextlib import redirect_stderr
import io
import logging
from pathlib import Path
import writer_session_fence as fence


def test_proof_refusal_in_process_without_handlers_has_empty_stderr(monkeypatch, capfd):
    # Only pytest/iwrun root handlers are cleared; module handlers and propagate stay intact.
    monkeypatch.setattr(logging.root, "handlers", [])
    logger = logging.getLogger(fence.__name__)
    handlers = []
    while logger is not None:
        handlers.extend(logger.handlers)
        if not logger.propagate:
            break
        logger = logger.parent
    assert len(handlers) <= 1 and all(isinstance(h, logging.NullHandler) for h in handlers)
    assert logging.lastResort is logging._defaultLastResort

    def fail(*args):
        raise OSError("private diagnostic must not escape")

    monkeypatch.setattr(fence, "_acquire_named_mutex", fail)
    scope = fence._FailedInstallerRemoval(Path.cwd(), Path.cwd())
    captured_stderr = io.StringIO()
    with redirect_stderr(captured_stderr):
        assert not scope.admits("current_user_setup_removal", Path.cwd(), {
            "status": "INSTALLING", "owner_kind": "canonical_installer",
            "session_authority_mutex_name": "unused-test-authority"})
    assert capfd.readouterr().err == ""
    stderr = captured_stderr.getvalue()
    assert stderr in ("", OSError.__name__ + "\n")
    assert stderr == "", "lastResort wrote an uncontracted exception-name line"
