from __future__ import annotations

import pytest

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit


class FakeWidget:
    """Tk-shaped login widget recorder that never opens a display."""

    def __init__(self, master=None, *args, width=1, height=1, **kwargs):
        self.master = master
        self.options = dict(kwargs)
        self.pack_options = {}
        self.grid_options = {}
        self.grid_rows = {}
        self.grid_columns = {}
        self.bindings = {}
        self.children = []
        self.pixel_width = width
        self.pixel_height = height
        self.exists = True
        self.focused = False
        if isinstance(master, FakeWidget):
            master.children.append(self)

    def set_size(self, width, height):
        self.pixel_width = width
        self.pixel_height = height

    def pack(self, **kwargs):
        self.pack_options.update(kwargs)

    def pack_configure(self, **kwargs):
        self.pack_options.update(kwargs)

    def pack_forget(self):
        self.pack_options["mapped"] = False

    def grid(self, **kwargs):
        self.grid_options.update(kwargs)

    def grid_configure(self, **kwargs):
        self.grid_options.update(kwargs)

    def grid_rowconfigure(self, row, **kwargs):
        self.grid_rows.setdefault(row, {}).update(kwargs)

    def grid_columnconfigure(self, column, **kwargs):
        self.grid_columns.setdefault(column, {}).update(kwargs)

    def bind(self, sequence, callback, add=None):
        self.bindings[sequence] = (callback, add)

    def configure(self, **kwargs):
        self.options.update(kwargs)

    config = configure

    def focus(self):
        self.focused = True

    def winfo_children(self):
        return list(self.children)

    def winfo_exists(self):
        return self.exists

    def winfo_width(self):
        return self.pixel_width

    def winfo_height(self):
        return self.pixel_height

    def destroy(self):
        self.exists = False
        if isinstance(self.master, FakeWidget) and self in self.master.children:
            self.master.children.remove(self)


class FakeRoot(FakeWidget):
    def __init__(self, width, height):
        super().__init__(width=width, height=height)
        self.after_calls = []
        self.cancelled_jobs = []

    def after(self, delay, callback, *args):
        job = f"after-{len(self.after_calls) + 1}"
        self.after_calls.append((job, delay, callback, args))
        return job

    def after_idle(self, callback, *args):
        return self.after(0, callback, *args)

    def after_cancel(self, job):
        self.cancelled_jobs.append(job)


class FakeStringVar:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeWorkerRegistry:
    @staticmethod
    def list_workers():
        return ["테스트 작업자"]


def _factory(*args, **kwargs):
    return FakeWidget(*args, **kwargs)


@pytest.fixture
def worker_login_view(monkeypatch):
    for name in ("Frame", "Label", "Button", "Combobox"):
        monkeypatch.setattr(container_audit_module.ttk, name, _factory)
    monkeypatch.setattr(container_audit_module.tk, "StringVar", FakeStringVar)
    monkeypatch.setattr(container_audit_module.ImageTk, "PhotoImage", lambda image: image)

    app = ContainerAudit.__new__(ContainerAudit)
    app.root = FakeRoot(1366, 768)
    app.scale_factor = 1.4
    app.logo_photo_ref = None
    app.worker_registry = FakeWorkerRegistry()
    app.worker_input_frame = FakeWidget(app.root, width=1346, height=718)
    app.paned_window = FakeWidget(app.root, width=1346, height=718)
    app._worker_login_layout_job = None
    app.show_worker_input_screen()
    return app


def _layout_snapshot(app):
    metrics = dict(app._worker_login_layout_metrics)
    return {
        "metrics": metrics,
        "logo_size": app._worker_login_logo_size,
        "center_padx": app._worker_login_center_frame.grid_options["padx"],
        "title_pady": app._worker_login_title_label.pack_options["pady"],
        "entry_ipady": app.worker_entry.pack_options["ipady"],
        "button_pady": app._worker_login_button_container.pack_options["pady"],
        "button_geometry": tuple(
            (button.pack_options["padx"], button.pack_options["ipady"])
            for button in app._worker_login_buttons
        ),
    }


def test_large_text_short_login_fixture_keeps_logo_and_actions_in_budget(worker_login_view):
    app = worker_login_view
    snapshot = _layout_snapshot(app)
    metrics = snapshot["metrics"]

    assert metrics["short_height"] is True
    assert metrics["estimated_content_height"] <= app.worker_input_frame.winfo_height() - 16
    assert snapshot["logo_size"][0] <= metrics["logo_max_width"]
    assert snapshot["logo_size"][1] <= metrics["logo_max_height"]
    assert snapshot["entry_ipady"] <= 8
    assert all(ipady <= 8 for _padx, ipady in snapshot["button_geometry"])
    assert app.worker_entry.focused is True
    assert "<Configure>" in app.worker_input_frame.bindings


def test_worker_login_fixture_compact_wide_compact_does_not_accumulate(worker_login_view):
    app = worker_login_view
    compact_before = _layout_snapshot(app)

    app.root.set_size(2560, 1080)
    app.worker_input_frame.set_size(2540, 1030)
    app._apply_worker_login_layout()
    wide = _layout_snapshot(app)

    app.root.set_size(1366, 768)
    app.worker_input_frame.set_size(1346, 718)
    app._apply_worker_login_layout()
    compact_after = _layout_snapshot(app)

    assert wide != compact_before
    assert compact_after == compact_before
