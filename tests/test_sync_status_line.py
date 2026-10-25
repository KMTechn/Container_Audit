"""Approved footer and catalog-notice contracts, without native Tk creation."""
import datetime
from types import SimpleNamespace

import pytest

import Container_Audit as ca
from direct_sync_health import RelayHealth, relay_health_detail_model
from tests.test_work_details_visibility import Widget, sidebar


NOW = datetime.datetime(2026, 10, 9, 16, 4, tzinfo=datetime.timezone.utc)


@pytest.fixture
def footer_app(monkeypatch):
    class Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz else NOW.astimezone().replace(tzinfo=None)

    monkeypatch.setattr(ca.datetime, "datetime", Clock)
    monkeypatch.setattr(ca.tkfont, "Font", lambda **kwargs: SimpleNamespace(
        measure=lambda text: len(text) * 8, actual=lambda name: 11,
    ))
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    app.root = Widget()
    app.root.width = 1366
    app.scale_factor = 1
    footer = Widget(app.root)
    footer.width = 1366
    app.status_label = Widget(footer, font=(app.DEFAULT_FONT, 11))
    app.direct_sync_status_label = Widget(footer)
    app.transfer_seal_coordinator = SimpleNamespace(client=SimpleNamespace(
        connection_state="normal", last_successful_transmission_at="",
    ))
    app._pending_seal_intent_count = 2
    return app


@pytest.mark.parametrize("width,short", [(1366, False), (1024, True)])
@pytest.mark.parametrize("connection,state,failed,review,oldest,long_text,short_text,tone", [
    ("disconnected", "review", 1, 2, "", "관리자 확인 필요 3건 · 보낼 것 5건", "관리자 확인 3건", "review"),
    ("disconnected", "pending", 0, 0, "", "회사 서버 연결 안 됨 · 이 PC에 저장 중 · 보낼 것 5건", "연결 안 됨 · 보낼 것 5건", "disconnected"),
    ("normal", "pending", 0, 0, (NOW - datetime.timedelta(minutes=11)).isoformat(), "회사 서버로 못 보낸 것 5건", "못 보낸 것 5건", "delayed"),
    ("unknown", "pending", 0, 0, "", "회사 서버: 첫 이적 때 확인", "첫 이적 때 확인", "neutral"),
    ("normal", "pending", 0, 0, (NOW - datetime.timedelta(minutes=1)).isoformat(), "회사 서버 연결됨 · 보낼 것 5건", "연결됨 · 5건", "neutral"),
])
def test_five_footer_states_have_approved_text_and_colors(
    footer_app, width, short, connection, state, failed, review, oldest, long_text, short_text, tone,
):
    app = footer_app
    app.root.width = app.direct_sync_status_label.parent.width = width
    app.transfer_seal_coordinator.client.connection_state = connection
    app._apply_direct_sync_health(RelayHealth(state, 3, failed, review, "", oldest, ""))
    options = app.direct_sync_status_label.options
    assert options["text"] == (short_text if short else long_text)
    assert "\n" not in options["text"] and "…" not in options["text"]
    assert "마지막 성공 전송 없음" not in options["text"]
    assert options["fg"] == {
        "review": app.COLOR_DANGER, "disconnected": app.COLOR_IDLE_TEXT,
        "delayed": app.COLOR_IDLE_TEXT, "neutral": app.COLOR_TEXT_SUBTLE,
    }[tone]
    assert options["bg"] == (app.COLOR_IDLE_BG if tone == "disconnected" else app.COLOR_SIDEBAR_BG)
    assert ("bold" in options["font"]) is (tone == "review")


@pytest.mark.parametrize("width,initial,connected,disconnected", [
    (1366, "회사 서버: 첫 이적 때 확인", "회사 서버 연결됨 · 보낼 것 0건",
     "회사 서버 연결 안 됨 · 이 PC에 저장 중 · 보낼 것 0건"),
    (1024, "첫 이적 때 확인", "연결됨 · 0건", "연결 안 됨 · 보낼 것 0건"),
])
def test_idle_footer_stays_neutral_until_transfer_client_has_a_result(
    footer_app, width, initial, connected, disconnected,
):
    app = footer_app
    app.root.width = app.direct_sync_status_label.parent.width = width
    app._pending_seal_intent_count = 0
    client = app.transfer_seal_coordinator.client
    client.connection_state = "unknown"
    app._render_direct_sync_status_line()
    assert app.direct_sync_status_label.options["text"] == initial
    for _ in range(3):
        app._apply_direct_sync_health(RelayHealth("ready", 0, 0, 0, "", "", ""))
        assert app.direct_sync_status_label.options["text"] == initial
        assert client.connection_state == "unknown"
    for connection, expected in (
        ("normal", connected), ("disconnected", disconnected), ("normal", connected),
    ):
        client.connection_state = connection
        app._apply_direct_sync_health(RelayHealth("ready", 0, 0, 0, "", "", ""))
        assert app.direct_sync_status_label.options["text"] == expected


def test_footer_zero_pending_and_unknown_counts_are_distinct(footer_app):
    app = footer_app
    app._pending_seal_intent_count = 0
    app._apply_direct_sync_health(RelayHealth("ready", 0, 0, 0, "", "", ""))
    assert app.direct_sync_status_label.options["text"] == "회사 서버 연결됨 · 보낼 것 0건"
    del app._direct_sync_last_read_health
    app._apply_direct_sync_health(RelayHealth("blocked", 0, 0, 0, "", "", "", "relay_health_read_failed"))
    assert app.direct_sync_status_label.options["text"] == "회사 서버 연결됨"
    assert "0건" not in app.direct_sync_status_label.options["text"]


@pytest.mark.parametrize("width", [1366, 1024])
@pytest.mark.parametrize("count", [0, 2])
def test_footer_reports_only_positive_file_error_counts_and_preserves_them_on_read_failure(
    footer_app, width, count,
):
    app = footer_app
    app.root.width = app.direct_sync_status_label.parent.width = width
    app._apply_direct_sync_health(RelayHealth("ready", 0, 0, 0, "", "", "", scan_file_error_count=count))
    text = app.direct_sync_status_label.options["text"]
    if count:
        assert text.endswith(" · 기록 파일 2개 안 올라감")
    else:
        assert "기록 파일" not in text
    app._apply_direct_sync_health(RelayHealth("blocked", 0, 0, 0, "", "", "", "relay_health_read_failed"))
    assert app._direct_sync_health.scan_file_error_count == count
    assert app.direct_sync_status_label.options["text"] == text


@pytest.mark.parametrize("days", [0, 1])
def test_last_transmission_appears_only_for_delayed_state_in_local_time(footer_app, days):
    app = footer_app
    sent = NOW - datetime.timedelta(days=days, minutes=12)
    app.transfer_seal_coordinator.client.last_successful_transmission_at = sent.isoformat()
    health = RelayHealth("pending", 3, 0, 0, "", (NOW - datetime.timedelta(minutes=11)).isoformat(), "")
    app._apply_direct_sync_health(health)
    local = sent.astimezone()
    expected = local.strftime("%H:%M") if local.date() == NOW.astimezone().date() else f"{local.month}. {local.day}. {local:%H:%M}"
    assert app.direct_sync_status_label.options["text"] == f"회사 서버로 못 보낸 것 5건 · 마지막 전송 {expected}"
    app._apply_direct_sync_health(RelayHealth("ready", 0, 0, 0, sent.isoformat(), "", ""))
    assert "마지막 전송" not in app.direct_sync_status_label.options["text"]
    app.root.width = 1024
    app._render_direct_sync_status_line()
    assert app.direct_sync_status_label.options["text"] == "연결됨 · 2건"


def test_wide_footer_uses_short_form_when_left_status_consumes_space(footer_app):
    app = footer_app
    app.status_label.winfo_reqwidth = lambda: 1250
    app._apply_direct_sync_health(RelayHealth("ready", 0, 0, 0, "", "", ""))
    assert app.direct_sync_status_label.options["text"] == "연결됨 · 2건"


def test_footer_is_in_separate_bottom_frame_and_sidebar_has_no_sync_card(monkeypatch, sidebar):
    app = sidebar
    for name in ("Frame", "Label"):
        monkeypatch.setattr(ca.tk, name, Widget)
    monkeypatch.setattr(ca.ttk, "PanedWindow", Widget)
    app.root = Widget()
    app._setup_core_ui_structure()
    assert app.direct_sync_status_label.options["text"] == "회사 서버: 첫 이적 때 확인"
    footer = app.direct_sync_status_label.parent
    assert footer is app.status_label.parent
    assert footer.parent is app.root
    assert footer.pack_options["side"] == ca.tk.BOTTOM
    assert app.direct_sync_status_label.pack_options["side"] == ca.tk.RIGHT
    assert app.root.children[0] is footer
    app._create_right_sidebar_content(Widget())
    assert "direct_sync" not in app.info_cards
    assert not hasattr(app, "direct_sync_details_button")
    assert not app.catalog_notice_frame.visible
    assert not app.catalog_notice_label.visible


def test_catalog_notice_keeps_first_line_and_buttons_in_short_sidebar(sidebar):
    app = sidebar
    parent = Widget()
    parent.height = 220
    app._create_right_sidebar_content(parent)
    app._startup_item_catalog_context = {
        "cache_used": True, "catalog_source": "VERIFIED_CACHE",
        "cache_last_modified_utc": NOW.isoformat(),
    }
    app.catalog_notice_details_label.requested_height = 80
    app._apply_direct_sync_health(RelayHealth("ready", 0, 0, 0, "", "", ""))
    assert app.catalog_notice_frame.grid_options["row"] == 3
    assert app.catalog_notice_frame.visible and app.catalog_notice_label.visible
    assert "회사 서버 품목 목록을 받지 못해" in app.catalog_notice_label.options["text"]
    assert app.catalog_notice_label.options["style"] == "RelayAttention.Value.TLabel"
    assert app.catalog_notice_details_label.options["style"] == "RelayAttention.Value.TLabel"
    assert not app.catalog_notice_details_label.visible
    assert app.work_details_button.visible and app.logistics_progress_button.visible
    assert parent.row_options[5]["minsize"] >= app.work_details_button.winfo_reqheight()
    assert parent.row_options[8]["minsize"] >= app.logistics_progress_button.winfo_reqheight()
    assert app.catalog_notice_label.options["wraplength"] <= parent.width
    parent.height = 768
    app._apply_catalog_notice_layout()
    assert app.catalog_notice_details_label.visible
    assert "저장된 목록 시각" in app.catalog_notice_details_label.options["text"]
    slots = [(id(widget.parent), widget.grid_options.get("row"), widget.grid_options.get("column"))
             for widget in parent.children if widget.visible and widget.grid_options]
    assert len(slots) == len(set(slots))
    app._startup_item_catalog_context = {}
    app._apply_direct_sync_health(RelayHealth("ready", 0, 0, 0, "", "", ""))
    assert not app.catalog_notice_frame.visible and not app.catalog_notice_label.visible
    assert not app.catalog_notice_details_label.visible


@pytest.mark.parametrize("height", [220, 768])
def test_catalog_notice_refresh_changes_layout_only_on_state_transition(sidebar, monkeypatch, height):
    app = sidebar
    parent = Widget()
    parent.height = height
    app._create_right_sidebar_content(parent)
    app.catalog_notice_details_label.requested_height = 80
    watched = (app.catalog_notice_frame, app.catalog_notice_label, app.catalog_notice_details_label)
    calls = []
    for name in ("configure", "grid", "grid_remove", "grid_rowconfigure"):
        original = getattr(Widget, name)

        def record(widget, *args, _name=name, _original=original, **options):
            if widget in watched or (widget is parent and _name == "grid_rowconfigure" and options):
                calls.append((_name, id(widget), args, dict(options)))
            return _original(widget, *args, **options)

        monkeypatch.setattr(Widget, name, record)

    health = RelayHealth("ready", 0, 0, 0, "", "", "")

    def refresh():
        app._apply_right_sidebar_layout()
        app._apply_direct_sync_health(health)

    def snapshot():
        return ([dict(widget.grid_info()) for widget in watched],
                {row: dict(options) for row, options in parent.row_options.items()},
                [widget.visible for widget in watched], len(calls))

    refresh()
    initial = snapshot()
    for _ in range(10):
        refresh()
        assert snapshot() == initial
    app._startup_item_catalog_context = {
        "cache_used": True, "catalog_source": "VERIFIED_CACHE",
        "cache_last_modified_utc": NOW.isoformat(),
    }
    refresh()
    notice = snapshot()
    assert notice[3] > initial[3]
    assert notice[2] == [True, True, height == 768]
    assert parent.row_options[3]["minsize"] > 0
    assert app.work_details_button.visible and app.logistics_progress_button.visible
    for _ in range(10):
        refresh()
        assert snapshot() == notice
    app._startup_item_catalog_context = {}
    refresh()
    cleared = snapshot()
    assert cleared[3] > notice[3] and cleared[2] == [False, False, False]
    assert parent.row_options[3]["minsize"] == 0
    for _ in range(10):
        refresh()
        assert snapshot() == cleared


def test_details_preserve_relay_fields_and_add_two_approved_lines(footer_app, monkeypatch):
    app = footer_app
    health = RelayHealth("pending", 3, 1, 2, NOW.isoformat(), "", NOW.isoformat())
    app._startup_item_catalog_context = {"cache_last_modified_utc": NOW.isoformat()}
    app.transfer_seal_coordinator.client.last_successful_transmission_at = NOW.isoformat()
    app._apply_direct_sync_health(health)
    messages = []
    monkeypatch.setattr(ca.messagebox, "showinfo", lambda title, text, **kwargs: messages.append((title, text)))
    app._schedule_focus_return = lambda: None
    app._show_direct_sync_status_details()
    assert messages[0][0] == "전송 상태 상세"
    lines = messages[0][1].splitlines()
    original = relay_health_detail_model(health, last_read_health=health)
    assert lines[:len(original)] == [f"{label}: {value}" for label, value in original.items()]
    timestamp = ca._item_catalog_cache_time_for_display(NOW.isoformat())
    assert lines[len(original):] == [f"저장된 목록 시각: {timestamp}", f"마지막 성공 전송: {timestamp}"]
