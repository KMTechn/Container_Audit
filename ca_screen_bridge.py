"""이적 새 화면 처리 층 이음 — 셸 host(owner_main 꼴) · km-app-contract/1(ui/app/ca/contract.json).

w9uiflow1014, APP-SCREENS-1013 ③. 처리 층(Container_Audit.ContainerAudit)의 규칙 · 저장 · 대기열 · 동기화는 그대로 두고
이 파일은 (1) 화면 한 덩어리 state 를 모으고(present_ca — 읽기만) (2) 화면 요청을 지금 처리 함수로 옮기기만 한다.

주인 스레드 = Tk 스레드(owner_main 이 그 스레드에서 앱을 만들고 root.after 로 bridge.pump()). 아래는 모두 그 스레드에서만 불린다.
- 스캔 문: 지금 시험과 같은 길 — scan_entry 에 넣고 process_barcode()(빈 Enter · 띠 선택 중 · 경고 중 판정은 처리 층 그대로).
  빈 Enter(막는 알림 확인)는 command('ack') — 같은 문에 빈 글.
- 단추: 숨긴 Tk 단추 invoke() — 허용 규칙 · 바뀌는 명령(제출 ↔ 다시 하기)이 지금과 같다. 단추 아닌 것(교환 · 리셋 · 품목 새로 고침 ·
  관리자 ▾)은 지금 운영 메뉴(_show_operations_menu)를 띄우지 않는 기록 메뉴로 한 번 돌려 그 항목의 켜짐 · 명령을 쓴다.
- PIN: 인스턴스의 _prompt_blocked_work_admin_pin 을 admin() 인수로 대신(불변식 1 「Tk 모달 PIN → admin()」, 값은 남기지 않음).
- messagebox · simpledialog · filedialog: 모듈 이름을 화면 어댑터로(불변식 1 「messagebox → push 알림」) — show* = 띠 · 관리자 판 결과,
  ask* = state.sheet 로 묻고 Tk 변수로 기다림(지금 Tk 대화상자와 같은 기다림), 파일 고르기 = 새 화면에 없음(그만두기).
- 바뀜 알림: 주인 스레드 0.25초마다 가벼운 지문을 견주어 바뀌면 bridge.push_state(reason='changed').
- 소리: 지금처럼 처리 층(native_audio)이 낸다 — scan 답 sound=None 이라 셸은 따로 내지 않음.
"""

from __future__ import annotations

from contextvars import copy_context
import datetime
import hashlib
import json
import os
import re
import time
import sys
import threading
import tkinter as tk
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import Container_Audit as ca
from screen_startup_fallback import ScreenLaunchAttempt, ScreenStartupUnavailable
from tk_callback_result import invoke_button_callback
from writer_session_fence import writer_admission
from scan_display import compact_scan_value
from warning_presenter import CompletionOutcome, NoticeSeverity

APP_DIR = Path(__file__).resolve().parent
PAGE = APP_DIR / "ui" / "app" / "ca" / "index.html"
CONTRACT = APP_DIR / "ui" / "app" / "ca" / "contract.json"
WATCH_MS = 250
LIST_LIMIT = 200

# ── 새 화면 낱말 ─────────────────────────────────────────────
CHOICE_IDS = {
    "작업자 변경": "change_worker", "작업 계속": "continue", "이어서 작업": "resume", "보류하고 새 작업": "park_new",
    "로그인 화면": "pick_worker", "원본 보존": "preserve", "실물 확인 후 재출력": "f8_reprint",
    "보류하고 이어서 작업": "park_resume", "현재 작업 유지": "keep_current", "꺼냈습니다": "cofill_overflow_ack",
}
CHOICE_TEXT = {"로그인 화면": "작업자 고르기"}  # 새 화면엔 로그인 화면이 없다 — 작업자 고르기 화면
RESULT_KIND = {NoticeSeverity.SUCCESS: "ok", NoticeSeverity.INFO: "idle", NoticeSeverity.WARNING: "warn", NoticeSeverity.ERROR: "bad"}
BAND_KIND = {NoticeSeverity.SUCCESS: "quiet", NoticeSeverity.INFO: "quiet", NoticeSeverity.WARNING: "warn", NoticeSeverity.ERROR: "bad"}
SOUND_TEXT = {"success": "성공음", "completion": "완료음", "error": "오류음"}
ADMIN_MENU = ("quarantine_hold", "pair_hold", "preserve_check", "defer_unsettled", "resend_completion",
              "recheck_review", "list_paired", "check_unsettled", "view_handoff", "view_sync")
ADMIN_PIN = frozenset(ADMIN_MENU[:7]) - {"resend_completion"}
# 지금 운영 메뉴 글(앞부분) → 다리 이름. 같은 이름 여럿이면 켜진 첫 항목(보존 다시 확인 · 다시 시도 · 계속 셋 중 지금 맞는 것)
MENU_LABELS = (
    ("보류 묶음 격리 후 다른 작업 계속", "quarantine_hold"), ("두 원본 함께 보류 후 계속", "pair_hold"),
    ("현재 현품표 보존 재확인", "preserve_check"), ("현재 현품표 보존 다시 시도", "preserve_check"),
    ("보류 후 다른 현품표 계속", "preserve_check"), ("미확정 묶음 보류 후 다른 작업 계속", "defer_unsettled"),
    ("완료 작업 회사 서버 반영 재시도", "resend_completion"), ("관리자 확인 다시 조회", "recheck_review"),
    ("관리자 짝 원본 보류 목록", "list_paired"), ("원 요청 결과 다시 확인", "check_unsettled"),
    ("관리자 인계 내용 보기", "view_handoff"), ("전송 상태 상세", "view_sync"),
    ("품목 목록 새로 고침", "refresh"), ("현재 작업 리셋", "reset"), ("개별 제품 교환", "exchange"),
    ("현재 이적 제품 교체", "exchange"), ("현품표 교체 (F8)", "f8"),
)


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name, default)
    except Exception:  # Tk 변수 · 지연 속성이 이미 닫혔을 때
        return default


def _widget_enabled(app: Any, name: str) -> Optional[bool]:
    widget = _attr(app, name)
    if widget is None:
        return None
    try:
        return str(widget["state"]) != str(tk.DISABLED)
    except Exception:
        return None


def _first_line(text: str) -> str:
    return str(text or "").strip().split("\n")[0].strip()


# ── 운영 메뉴 읽기(띄우지 않음) ──────────────────────────────
class _MenuRecorder:
    """_show_operations_menu 가 만든 메뉴를 띄우지 않고 항목만 받는다(주인 스레드 · 그 부름 동안만 tk.Menu 를 대신)."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.entries: List[Tuple[str, Optional[Callable[[], Any]], str]] = []

    def add_command(self, label: str = "", command: Optional[Callable[[], Any]] = None, state: Any = tk.NORMAL, **_kw: Any) -> None:
        self.entries.append((str(label), command, str(state)))

    def __getattr__(self, _name: str) -> Callable[..., None]:  # add_separator · tk_popup · grab_release · destroy …
        return lambda *_a, **_k: None


def operations_menu(app: Any) -> Dict[str, Tuple[bool, Optional[Callable[[], Any]]]]:
    """지금 운영 메뉴 → {다리 이름: (켜짐, 명령)}. 메뉴 조건은 처리 층 그대로(복사하지 않음)."""
    recorders: List[_MenuRecorder] = []
    original = tk.Menu

    def make(*args: Any, **kwargs: Any) -> _MenuRecorder:
        recorder = _MenuRecorder(*args, **kwargs)
        recorders.append(recorder)
        return recorder

    tk.Menu = make  # type: ignore[misc,assignment]
    try:
        app._show_operations_menu()
    except Exception:
        return {}
    finally:
        tk.Menu = original  # type: ignore[misc]
    out: Dict[str, Tuple[bool, Optional[Callable[[], Any]]]] = {}
    for recorder in recorders:
        for label, command, state in recorder.entries:
            for prefix, name in MENU_LABELS:
                if label.startswith(prefix):
                    enabled = state != str(tk.DISABLED) and command is not None
                    if name not in out or (enabled and not out[name][0]):
                        out[name] = (enabled, command)
                    break
    return out


# ── state 모으기 ─────────────────────────────────────────────
def _conn(app: Any) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """바닥 서버 줄 — 지금 _render_direct_sync_status_line(CA:17744) 갈래 그대로, 글 고르기는 틀 기본 글."""
    health = _attr(app, "_direct_sync_health")
    known = isinstance(health, ca.RelayHealth) and (
        not health.read_failed or isinstance(_attr(app, "_direct_sync_last_read_health"), ca.RelayHealth))
    pending = (health.pending_count + int(_attr(app, "_pending_seal_intent_count") or 0)) if known else 0
    review = (health.failed_permanent_count + health.operator_review_count) if known else 0
    client = _attr(_attr(app, "transfer_seal_coordinator"), "client")
    connection = _attr(client, "connection_state", "unknown")
    delayed = False
    if pending and isinstance(health, ca.RelayHealth):
        try:
            oldest = datetime.datetime.fromisoformat(health.oldest_pending_at.replace("Z", "+00:00")).astimezone()
            delayed = (datetime.datetime.now().astimezone() - oldest).total_seconds() > 600
        except (ValueError, AttributeError, TypeError):
            pass
    if review:
        state = "review"
    elif connection == "disconnected":
        state = "offline"
    elif connection == "normal":
        state = "late" if delayed else "ok"
    else:
        state = "first"
    conn: Dict[str, Any] = {"state": state}
    if state == "first":
        conn["label"] = "회사 서버: 첫 이적 때 확인"
    return conn, {"pending": int(pending), "failed": int(review)}


def _sound_text(app: Any, last_sound: Optional[str]) -> Optional[str]:
    if _attr(app, "_warning_beep_active"):
        return "오류음 — 확인할 때까지 반복"
    return SOUND_TEXT.get(last_sound or "")


def _choices(app: Any) -> List[Dict[str, Any]]:
    out = []
    for index, choice in enumerate(_attr(app, "_inline_scan_choices") or []):
        text = str(choice[0])
        choice_id = CHOICE_IDS.get(text, f"choice-{index}")
        out.append({"id": choice_id, "text": CHOICE_TEXT.get(text, text), "go": f"command:choose:{choice_id}",
                    **({"default": True} if text in {"작업 계속", "이어서 작업", "현재 작업 유지"} else {})})
    return out


def _alerts(app: Any, presenter_state: Any, notes: List[Dict[str, Any]], now: datetime.datetime) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    notice = presenter_state.active_notice
    if notice is not None and notice.blocking:
        choices = _choices(app)
        band: Dict[str, Any] = {"kind": "bad" if notice.severity is NoticeSeverity.ERROR else "warn",
                                "text": f"{notice.title} — {_first_line(notice.message)}"}
        if choices:
            band["choices"] = choices
            band["tail"] = "다음 스캔 = " + next((c["text"] for c in choices if c.get("default")), choices[-1]["text"])
        elif not app._operator_review_blocks_mutation():
            band["choices"] = [{"id": "ack", "text": "확인", "go": "command:ack", "default": True}]
            band["tail"] = "빈 Enter · Esc = 확인"
        alerts.append(band)
    undo = _attr(app, "_short_confirmation_undo")
    if undo:
        try:
            left = int(app._short_confirmation_remaining(undo.get("contract") or undo))
        except Exception:
            left = 0
        alerts.append({"kind": "strong", "text": "부족한 채로 확정합니다 — 60초 안에는 「마지막 스캔 취소」로 되돌릴 수 있습니다",
                       "tail": f"{left}초 남음"})
    if _attr(app, "is_idle"):
        alerts.append({"kind": "quiet", "text": "휴식 상태 — 스캔하면 작업을 다시 시작합니다", "tail": "7분 넘게 스캔 없음"})
    try:
        catalog = _first_line(app._catalog_notice_for_display())
    except Exception:
        catalog = ""
    if catalog:
        alerts.append({"kind": "warn", "text": catalog})
    for note in notes[-1:]:  # 처리 층 알림(지금 messagebox 자리) — 가장 최근 하나, 「확인」 으로 닫음
        alerts.append({"kind": note["kind"], "text": note["text"],
                       "choices": [{"id": "note_ok", "text": "확인", "go": "command:choose:note_ok", "default": True}]})
    return alerts[:4]


def _list(tray: Any, now: datetime.datetime) -> List[Dict[str, Any]]:
    barcodes = list(_attr(tray, "scanned_barcodes") or [])
    times = list(_attr(tray, "scan_times") or [])
    item_code = _attr(tray, "item_code", "")
    rows = []
    for index in range(len(barcodes) - 1, max(-1, len(barcodes) - 1 - LIST_LIMIT), -1):
        compact = compact_scan_value(barcodes[index], item_code=item_code)
        at = times[index].strftime("%H:%M:%S") if index < len(times) and isinstance(times[index], datetime.datetime) else ""
        rows.append({"no": str(index + 1), "code": compact.split(" · ")[-1], "at": at,
                     "st": "new" if index == len(barcodes) - 1 else "ok"})
    return rows


def _work(app: Any, presenter_state: Any, last_sound: Optional[str], now: datetime.datetime) -> Dict[str, Any]:
    tray = _attr(app, "current_tray")
    tag = str(_attr(tray, "master_label_code", "") or "")
    checking = bool(_attr(app, "_master_preflight_pending"))
    completion = presenter_state.completion
    done = not tag and completion is not None and not completion.blocks_completion
    exchange = str(_attr(app, "_inline_exchange_mode", "") or "")
    short = bool(_attr(app, "_short_confirmation_undo"))
    if done:
        item = {"name": completion.item_name, "spec": "", "code": ""} if completion.item_name else None
        target, count, tag_out = completion.target_count, completion.scan_count, completion.master_label or None
        rows: List[Dict[str, Any]] = []
    else:
        name = str(_attr(tray, "item_name", "") or "")
        item = {"name": name, "spec": str(_attr(tray, "item_spec", "") or ""), "code": str(_attr(tray, "item_code", "") or "")} if tag and name else None
        target = int(_attr(tray, "tray_size", 0) or 0) if tag and not checking else 0
        count = len(_attr(tray, "scanned_barcodes") or []) if tag else 0
        tag_out = tag or None
        rows = _list(tray, now) if tag else []
    if checking:
        snapshot = _attr(app, "_preflight_hold_snapshot")
        held = list(_attr(snapshot, "items", ()) or ())
        rows = [{"no": str(h.sequence), "code": compact_scan_value(h.raw_barcode, item_code="").split(" · ")[-1],
                 "at": str(h.admitted_at)[11:19], "st": "held", "tag": "보관"} for h in reversed(held)][:LIST_LIMIT]
    mode = "swap1" if exchange == "old" else "swap2" if exchange == "new" else "short" if short else "done" if done else None
    target_code = str(_attr(app, "_inline_exchange_target", "") or "")
    if mode == "swap2" and target_code:  # 교환 ② 단계 — 뺄 불량 제품 줄을 표시
        barcodes = list(_attr(tray, "scanned_barcodes") or [])
        for row in rows:
            index = int(row["no"]) - 1
            if 0 <= index < len(barcodes) and barcodes[index] == target_code:
                row.update(st="swap", tag="교환 중")
    if not item:
        left_kind, remaining = "none", None
    elif not target:
        left_kind, remaining = "target_pending", None
    elif short:
        left_kind, remaining = "short", max(0, target - count)
    elif count >= target:
        left_kind, remaining = "full", None
    else:
        left_kind, remaining = "remaining", target - count
    busy = bool(_attr(app, "_completion_lane_busy"))
    if done:
        nxt, sub = "완료 — 다음 현품표를 스캔하세요", [{"text": "이 트레이는 끝났습니다"}]
    elif not tag and not checking:
        nxt, sub = "현품표를 스캔하세요", [{"text": "현품표를 찍으면 품목과 목표 수가 나옵니다"}]
    elif checking:
        nxt, sub = "제품을 스캔하세요", [{"text": "현품표 확인 중 — 먼저 찍은 제품은 찍은 순서대로 보관했다가 확인되면 넣습니다"}]
    elif mode == "swap1":
        nxt, sub = "교환 — 불량 제품을 스캔하세요", [{"text": "① 불량 제품", "on": True}, {"text": "  →  "}, {"text": "② 대체품", "off": True}]
    elif mode == "swap2":
        nxt, sub = "대체품을 스캔하세요", [{"text": "① 불량 제품", "off": True}, {"text": "  →  "}, {"text": "② 대체품", "on": True}]
    elif short:
        nxt, sub = "다음 현품표를 스캔하세요", [{"text": "다음 현품표를 찍으면 바로 확정됩니다"}]
    elif target and count >= target:
        nxt = "회사 서버 이적 확인 중 — 트레이를 그대로 두세요" if busy else "다 찍었습니다 — 「트레이 제출」 을 누르세요"
        sub = [{"text": f"{item['name'] if item else ''} · {count}개"}]
    else:
        nxt, sub = "제품을 스캔하세요", [{"text": f"목표 {target}개"}]
    return {
        "tag": tag_out, "item": item, "target": target, "count": count, "remaining": remaining, "left_kind": left_kind,
        "list_count": len(rows) if checking else count, "mode": mode, "checking": checking, "next": nxt, "next_sub": sub,
        "result": _result(app, presenter_state, tray, count, last_sound), "list": rows, "cofill": None,
    }


def _result(app: Any, presenter_state: Any, tray: Any, count: int, last_sound: Optional[str]) -> Dict[str, Any]:
    notice = presenter_state.active_notice
    sound = _sound_text(app, last_sound)
    out: Dict[str, Any]
    completion = presenter_state.completion
    if notice is not None and notice.code.startswith("completion.") and completion is not None:
        if completion.outcome is CompletionOutcome.ACKED:
            out = {"kind": "ok", "text": "완료 · 회사 서버 확인됨", "sub": f"{completion.item_name} · {completion.scan_count}개"}
        elif completion.outcome is CompletionOutcome.LINKED:
            supplement = _attr(app, "_last_shipping_supplement_intent", "")
            if supplement and supplement not in (_attr(app, "_shipping_confirmed_intents", set()) or set()):
                out = {"kind": "warn", "text": "완료 · 출고 전 관리자 보충 필요", "sub": f"이 PC에 저장 · {completion.item_name} · {completion.scan_count}개"}
            else:
                out = {"kind": "saved", "text": "완료 · 이 PC에 저장", "sub": "회사 서버로 저절로 다시 보냅니다"}
        else:
            out = {"kind": RESULT_KIND[notice.severity], "text": notice.title, "sub": _first_line(notice.message)}
    elif notice is not None:
        text = notice.title if notice.blocking else _first_line(notice.message)
        out = {"kind": RESULT_KIND[notice.severity], "text": text, "sub": _first_line(notice.message) if notice.blocking else ""}
    elif presenter_state.last_normal_scan and _attr(tray, "master_label_code"):
        times = list(_attr(tray, "scan_times") or [])
        at = times[-1].strftime("%H:%M:%S") if times and isinstance(times[-1], datetime.datetime) else ""
        code = compact_scan_value(presenter_state.last_normal_scan, item_code=_attr(tray, "item_code", "")).split(" · ")[-1]
        out = {"kind": "ok", "text": f"맞음 — {count}번째", "sub": f"{code} · {at}".strip(" ·")}
    else:
        out = {"kind": "idle", "text": "아직 찍은 것이 없습니다", "sub": "현품표를 찍으면 품목과 목표 수가 나옵니다"}
    if sound and out["kind"] != "idle":
        out["sound"] = sound
    if not out.get("sub"):
        out.pop("sub", None)
    return out


def _allow(app: Any, menu: Dict[str, Tuple[bool, Any]], work: Dict[str, Any]) -> Dict[str, bool]:
    def button(name: str, fallback: bool) -> bool:
        enabled = _widget_enabled(app, name)
        return fallback if enabled is None else enabled

    def item(name: str) -> bool:
        return bool(menu.get(name, (False, None))[0])

    return {
        "exchange": item("exchange") and bool(work["tag"]), "undo": button("undo_button", False),
        "submit": button("submit_tray_button", False), "park": button("park_button", False),
        "f8": item("f8") or button("phs_label_exchange_button", False), "refresh": item("refresh"),
        "reset": item("reset"),
    }


def _held_count(app: Any) -> int:
    tree = _attr(app, "parked_tree")
    try:
        return len(tree.get_children()) if tree is not None else 0
    except Exception:
        return 0


def _view(app: Any, override: Optional[str]) -> str:
    if not str(_attr(app, "worker_name", "") or "").strip():
        return "start"
    if override:
        return override
    if _attr(app, "_progress_visible"):
        return "progress"
    if _attr(app, "_phs_label_exchange_panel_open"):
        return "f8"
    return "work"


def admin_facts(app: Any, name: str) -> List[List[str]]:
    """관리자 판 사실 줄 — 대상이 처리 층 값으로 분명한 것만. 나머지는 동작이 직접 보여 줌."""
    if name == "quarantine_hold":
        snapshot = _attr(app, "_preflight_hold_snapshot")
        if snapshot is None:
            return []
        held = len(_attr(snapshot, "items", ()) or ())
        return [["대상", f"현품표 확인 중 보관한 제품 {held}개"], ["따로 둔 뒤", "이 현품표는 관리자 확인 전까지 잠김"]]
    if name == "defer_unsettled":
        tray = _attr(app, "current_tray")
        tag = str(_attr(tray, "master_label_code", "") or "")
        if not tag:
            return []
        item = " ".join(part for part in (str(_attr(tray, "item_name", "") or ""), str(_attr(tray, "item_spec", "") or "")) if part)
        count = len(_attr(tray, "scanned_barcodes") or [])
        return [["현재 묶음", f"현품표 {tag} · {item} · 스캔 {count}".replace(" ·  · ", " · ")],
                ["보류 뒤", "같은 현품표는 관리자 확인 전까지 잠김"]]
    if name == "preserve_check" and _attr(app, "_paired_stale_current_blocked"):
        facts = []
        for label, attribute in (("현재 작업 원본", "_paired_stale_current_path"),
                                 ("보존 사본 이름", "_paired_stale_current_preserved_path")):
            path = str(_attr(app, attribute, "") or "")
            if path:
                facts.append([label, Path(path).name])
        return facts
    if name == "resend_completion":
        cases = _attr(app, "_transfer_post_review_cases", ()) or ()
        case = next((row for row in cases if row.get("command_bound")), None)
        if case is None:
            return []
        facts = []
        if case.get("item_id") is not None:
            facts.append(["품목", str(case["item_id"])])
        if case.get("scan_count") is not None:
            facts.append(["수량", f"{case['scan_count']}개"])
        return facts
    return []


def f8_values(app: Any) -> Dict[str, Any]:
    """지금 현품표 교체 판의 단계·안내만 읽는다. 없는 수량·받은 시각은 만들지 않는다."""
    loading = bool(_attr(app, "_phs_reconciliation_resolve_pending") or _attr(app, "_phs_label_candidate_pending"))
    executing = bool(_attr(app, "_phs_label_exchange_pending") or _attr(app, "_phs_label_refresh_pending"))
    recovery = bool(_attr(app, "_phs_label_exchange_recovery_visible"))
    ready = bool(_attr(app, "_phs_reconciliation_context") or _attr(app, "_phs_label_candidates"))
    if executing:
        next_step = "현품표 교체 처리 중입니다 — 잠시 기다리세요"
    elif loading:
        next_step = "회사 서버에서 교체 지시를 확인 중입니다"
    elif recovery:
        next_step = "실물과 프린터를 확인한 뒤 F8로 교체를 계속하세요"
    elif ready:
        next_step = "교체 지시를 확인한 뒤 F8을 누르세요"
    else:
        next_step = "바꿀 현재 또는 완료된 이적 현품표를 스캔하세요"
    sub = ""
    label = _attr(app, "phs_active_label_info_label")
    try:
        if label is not None:
            sub = str(label["text"] or "")
        if not sub:
            variable = _attr(app, "phs_label_candidate_var")
            if variable is not None:
                sub = str(variable.get() or "")
    except (tk.TclError, AttributeError, KeyError, TypeError):
        pass
    sub = sub.replace("서버 교체 지시", "회사 서버 교체 지시").replace(" Pcs", "개")
    if "API" in sub:
        sub = "현품표 교체를 사용할 수 없습니다 — 관리자에게 알리세요"
    # target가 있으면 화면은 완전한 plan도 요구한다. 처리 층에는 지시 받은 시각과
    # 한 덩어리의 전/후 수량·장수가 없어 둘 다 생략하고 기존 판 안내를 그대로 싣는다.
    return {"step": 2 if executing else 1 if loading else 2 if recovery or ready else 0,
            "stop": recovery and not (loading or executing), "next": next_step, "sub": sub, "card": "how"}


def roster_values(app: Any) -> Dict[str, Any]:
    """작업자 고르기 — 지금 명단 고르기(_worker_selection_names CA:3254) · 안내 글(CA:3268) · 최근 작업자(worker_registry.recent_worker)."""
    labels = [str(label) for label in app._worker_selection_names()][:500]
    try:
        recent = str(app.worker_registry.recent_worker() or "")
    except Exception:
        recent = ""
    try:
        note = _first_line(app._worker_roster_notice_text())
    except Exception:
        note = ""
    names = []
    for label in labels:
        row = {"id": label, "label": label}
        if recent and (label == recent or label.startswith(recent + " ")):
            row["last"] = True
        names.append(row)
    out: Dict[str, Any] = {"count": len(names), "at": "", "names": names}
    if note:
        out["note"] = note
    return out


def today_values(app: Any) -> Dict[str, Any]:
    """오늘 현황 — 지금 Tk 「금일 작업 현황」(CA:15980–16006)과 같은 원천. 품목별 제품 수는 처리 층에 없어 싣지 않는다."""
    confirmed = _attr(app, "_shipping_confirmed_intents", set()) or set()
    rows, supply = [], 0
    for _code, data in sorted((_attr(app, "work_summary", {}) or {}).items()):
        name = str(data.get("name", "") or "")
        spec = str(data.get("spec", "") or "")
        rows.append({"item": f"{name} · {spec}" if spec else name, "trays": max(0, int(data.get("count", 0) or 0))})
        supply += len(set(data.get("shipping_supplement_intents", set()) or set()) - set(confirmed))
    return {"total_trays": max(0, int(_attr(app, "total_tray_count", 0) or 0)), "rows": rows[:100], "supply": supply}


def progress_values(app: Any) -> Dict[str, Any]:
    """진행 현황 — 지금 Tk 패널이 그리는 _progress_data(CA:5665) 그대로. 남은 수량 · 상자는 회사 서버 값(화면은 셈하지 않음)."""
    data = _attr(app, "_progress_data") or {}
    tray_code = str(_attr(_attr(app, "current_tray"), "item_code", "") or "")
    rows = []
    for item in list(data.get("items", []) or [])[:100]:
        row = {"item": str(item.get("name") or item.get("item_id") or ""), "plan": max(0, int(item.get("plan_qty") or 0)),
               "ready": max(0, int(item.get("transferred_qty") or 0)), "left": max(0, int(item.get("remaining_qty") or 0)),
               "trays_left": max(0, int(item.get("remaining_boxes") or 0))}
        if tray_code and str(item.get("item_id") or "") == tray_code:
            row["now"] = True
        rows.append(row)
    return {"date": str(data.get("date") or datetime.date.today().isoformat()),
            "conn": "off" if _attr(app, "_progress_disconnected") else "ok",
            "at": str(_attr(app, "_progress_last_success", "") or "")[-8:], "rows": rows}


def present_ca(app: Any, *, view: Optional[str] = None, menu: Optional[Dict[str, Tuple[bool, Any]]] = None,
               notes: Optional[List[Dict[str, Any]]] = None, sheet: Optional[Dict[str, Any]] = None,
               last_sound: Optional[str] = None, extra: Optional[Dict[str, Any]] = None,
               now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """contract.json 의 state 한 덩어리. 처리 층 값 · 숨긴 Tk 위젯 상태를 읽기만 한다(부작용 0)."""
    now = now or datetime.datetime.now()
    presenter_state = app._warning_state_presenter().state
    menu = menu if menu is not None else {}
    work = _work(app, presenter_state, last_sound, now)
    conn, queue = _conn(app)
    worker = str(_attr(app, "worker_name", "") or "").strip()
    state: Dict[str, Any] = {
        "app": "ca", "version": str(_attr(app, "APP_VERSION", "")), "last_request_seq": 0, "clock": now.strftime("%H:%M"),
        "view": _view(app, view), "worker": {"label": ca.display_operator_name(worker)} if worker else None,
        "legacy": bool(_attr(app, "legacy_label_transition")), "held_count": _held_count(app),
        "conn": conn, "queue": queue, "update": None,
        "alerts": _alerts(app, presenter_state, notes or [], now), "work": work, "allow": _allow(app, menu, work),
        "admin_menu": [{"name": name, "enabled": bool(menu.get(name, (False, None))[0])
                        and (name != "resend_completion" or app._is_preflight_hold_supervisor()),
                        "facts": admin_facts(app, name)} for name in ADMIN_MENU],
        "sheet": sheet,
    }
    state.update(extra or {})
    return state


def fingerprint(app: Any, view: Optional[str], notes: List[Dict[str, Any]], sheet: Any) -> str:
    """0.25초 감시용 가벼운 지문 — 화면에 보이는 처리 층 값이 바뀌었는지(메뉴 · 파일 읽기 없이)."""
    tray = _attr(app, "current_tray")
    presenter_state = app._warning_state_presenter().state
    conn, queue = _conn(app)
    parts = (
        _attr(tray, "master_label_code"), len(_attr(tray, "scanned_barcodes") or []), _attr(tray, "tray_size"),
        repr(presenter_state), _attr(app, "_inline_exchange_mode"), bool(_attr(app, "_short_confirmation_undo")),
        bool(_attr(app, "_master_preflight_pending")), bool(_attr(app, "is_idle")), bool(_attr(app, "_warning_beep_active")),
        [c[0] for c in (_attr(app, "_inline_scan_choices") or [])], _attr(app, "worker_name"), _view(app, view),
        app._is_preflight_hold_supervisor(),
        conn, queue, _held_count(app), len(notes), json.dumps(sheet, ensure_ascii=False, sort_keys=True, default=str),
        {name: _widget_enabled(app, name) for name in ("undo_button", "submit_tray_button", "park_button")},
        f8_values(app) if _view(app, view) == "f8" else None,
        int(_attr(app, "_short_confirmation_undo") and 1 or 0) and datetime.datetime.now().second,
    )
    return hashlib.sha256(repr(parts).encode("utf-8", "replace")).hexdigest()


# ── 대화상자 어댑터 ──────────────────────────────────────────
class ScreenDialogs:
    """tkinter messagebox · simpledialog · filedialog 대신(이 모듈 이름 자리에 둔다). 처리 층 글은 그대로, 창은 띄우지 않는다."""

    def __init__(self) -> None:
        self.processor: Optional["CaProcessor"] = None
        self.early: List[Dict[str, Any]] = []  # 처리 층이 붙기 전(시작 중) 알림

    def _note(self, kind: str, title: Any, message: Any) -> str:
        note = {"kind": kind, "text": " — ".join(part for part in (_first_line(title), _first_line(message)) if part) or "확인하세요"}
        if self.processor is None:
            self.early.append(note)
        else:
            self.processor.note(note)
        return "ok"

    def showinfo(self, title: Any = None, message: Any = None, **_kw: Any) -> str:
        return self._note("quiet", title, message)

    def showwarning(self, title: Any = None, message: Any = None, **_kw: Any) -> str:
        return self._note("warn", title, message)

    def showerror(self, title: Any = None, message: Any = None, **_kw: Any) -> str:
        return self._note("bad", title, message)

    def _ask(self, title: Any, message: Any, yes: str, no: str) -> Optional[bool]:
        if self.processor is None:
            self._note("warn", title, message)
            return False  # 시작 중 물음 = 그만두기(지금 대화상자의 「아니오」 와 같음)
        return self.processor.ask(_first_line(title) or "확인", str(message or ""), yes, no)

    def askyesno(self, title: Any = None, message: Any = None, **_kw: Any) -> bool:
        return bool(self._ask(title, message, "예", "아니오"))

    def askokcancel(self, title: Any = None, message: Any = None, **_kw: Any) -> bool:
        return bool(self._ask(title, message, "확인", "그만두기"))

    def askretrycancel(self, title: Any = None, message: Any = None, **_kw: Any) -> bool:
        return bool(self._ask(title, message, "다시 하기", "그만두기"))

    def askquestion(self, title: Any = None, message: Any = None, **_kw: Any) -> str:
        return "yes" if self._ask(title, message, "예", "아니오") else "no"

    def askyesnocancel(self, title: Any = None, message: Any = None, **_kw: Any) -> Optional[bool]:
        return self._ask(title, message, "예", "아니오")

    # simpledialog — 이적의 입력 창(원 현품표 확인)은 새 화면에서 「스캔」 으로 받는다(CA-STATE §6)
    def askstring(self, title: Any = None, prompt: Any = None, **_kw: Any) -> Optional[str]:
        if self.processor is None:
            return None
        return self.processor.ask_scan(_first_line(title) or "스캔", str(prompt or ""))

    def askinteger(self, title: Any = None, prompt: Any = None, **_kw: Any) -> Optional[int]:
        text = self.askstring(title, prompt)
        try:
            return int(str(text).strip()) if text is not None else None
        except ValueError:
            return None

    # filedialog — 새 화면에 파일 고르기 없음(관리자 일은 관리자 화면에서)
    def askopenfilename(self, *_args: Any, **_kw: Any) -> str:
        self._note("warn", "파일 고르기", "이 일은 새 화면에서 하지 않습니다 — 관리자에게 알리세요")
        return ""

    askdirectory = asksaveasfilename = askopenfilename


class _Answer:
    """진짜 Tk 가 없을 때(시험 고정물)의 답 칸 — get · set 만."""

    def __init__(self) -> None:
        self.value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = str(value)


class _HiddenTk(tk.Tk):
    """처리 층의 Tk 뿌리 — 숨긴 채로만 산다(창은 새 화면 하나). 앱이 띄우려 해도 보이지 않는다."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        super().withdraw()

    def deiconify(self) -> None:
        return None

    def state(self, newstate: Optional[str] = None) -> str:  # zoomed · normal 로 띄우기 막음, 읽기는 그대로
        return super().state() if newstate is None else "withdrawn"

    def lift(self, *_args: Any) -> None:
        return None

    tkraise = lift

    def focus_force(self) -> None:
        return None


# ── 처리 층 객체(셸 host processor) ──────────────────────────
class CaProcessor:
    """셸 host 가 주인 스레드에서 부르는 넷(state · scan · command · admin) + closing."""

    def __init__(self, app: Any, *, bridge: Any = None, dialogs: Optional[ScreenDialogs] = None) -> None:
        self.app = app
        self.bridge = bridge
        self.dialogs = dialogs or ScreenDialogs()
        self.dialogs.processor = self
        self.notes: List[Dict[str, Any]] = list(self.dialogs.early)
        self.view: Optional[str] = None
        self.sheet: Optional[Dict[str, Any]] = None
        self.last_sound: Optional[str] = None
        self._answer: Optional[tk.StringVar] = None
        self._scan_answer: Optional[tk.StringVar] = None
        self._credentials: Optional[Tuple[str, str]] = None
        self._admin_notes: Optional[List[Dict[str, Any]]] = None
        self._fingerprint = ""
        self._registration_name: Optional[str] = None
        self._watch_job: Any = None

    # 설치 — 처리 층 파일은 고치지 않고 이 인스턴스 · 모듈 이름 자리만 바꾼다
    def install(self) -> None:
        app = self.app
        self._restore = [(name, getattr(ca, name)) for name in ("messagebox", "simpledialog", "filedialog", "play_sound")]
        ca.messagebox = self.dialogs  # type: ignore[assignment]
        ca.simpledialog = self.dialogs  # type: ignore[assignment]
        ca.filedialog = self.dialogs  # type: ignore[assignment]
        original_play = ca.play_sound
        sounds = {"success": "success_sound", "error": "error_sound", "completion": "completion_sound"}

        def play_sound(sound: Any, *args: Any, **kwargs: Any) -> Any:
            for name, attribute in sounds.items():
                if sound is not None and sound is _attr(app, attribute):
                    self.last_sound = name
            return original_play(sound, *args, **kwargs)

        ca.play_sound = play_sound  # type: ignore[assignment]
        app._prompt_blocked_work_admin_pin = self._take_credentials
        app._prompt_for_test_item = self._no_test_item
        self._watch_job = app.root.after(WATCH_MS, self._watch)

    def shutdown(self) -> None:
        for name, value in getattr(self, "_restore", []):
            setattr(ca, name, value)
        self._restore = []
        if self._watch_job is not None:
            try:
                self.app.root.after_cancel(self._watch_job)
            except Exception:
                pass
            self._watch_job = None

    # 바뀜 감시 → push_state
    def _watch(self) -> None:
        self._watch_job = None
        try:
            current = fingerprint(self.app, self.view, self.notes, self.sheet)
            if current != self._fingerprint:
                self._fingerprint = current
                if self.bridge is not None:
                    self.bridge.push_state(reason="changed")
        finally:
            try:
                self._watch_job = self.app.root.after(WATCH_MS, self._watch)
            except Exception:
                self._watch_job = None

    # host 넷 ──────────────────────────────────────────
    def state(self) -> Dict[str, Any]:
        extra = self._pane_values()
        return present_ca(self.app, view=self.view, menu=operations_menu(self.app), notes=self.notes,
                          sheet=self.sheet, last_sound=self.last_sound, extra=extra)

    def scan(self, text: str, info: Dict[str, Any]) -> Dict[str, Any]:
        raw = str(text or "")
        if self._scan_answer is not None:  # 판이 스캔을 기다리는 중(원 현품표 확인)
            self._scan_answer.set("scan:" + raw)
            return {"accepted": True, "verdict": None, "message": "", "sound": None, "result": None}
        if self._answer is not None:  # 물음이 열려 있음 — 스캔은 그만두기가 아니라 미접수(먼저 답)
            return {"accepted": False, "verdict": None, "message": "먼저 화면의 물음에 답하세요", "sound": None, "result": None}
        if self.view == "held":
            self.view = None  # 한 단계 안 화면에서 찍어도 작업 화면으로 돌아가 처리
        self._enter(raw)
        return {"accepted": True, "verdict": None, "message": "", "sound": None, "result": None}

    def command(self, name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        args = dict(args or {})
        handler = getattr(self, f"_cmd_{name}", None)
        if handler is None:
            return {"ok": False, "result": {"kind": "warn", "text": "이 단추는 아직 처리 층에 없습니다"}}
        out = handler(args.get("id"), args)
        return out if isinstance(out, dict) and type(out.get("ok")) is bool else self._action_reply(out, [])

    def admin(self, name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        args = dict(args or {})
        if name not in ADMIN_PIN:
            return {"ok": False, "result": {"kind": "warn", "text": "PIN 이 드는 관리자 일이 아닙니다"}}
        admin_id, pin = str(args.get("admin_id") or "").strip(), str(args.get("pin") or "")
        if not admin_id or len(pin) != 6 or not pin.isdigit():
            return {"ok": False, "result": {"kind": "warn", "text": "관리자 ID 와 PIN 6자리를 넣으세요"}}
        enabled, command = operations_menu(self.app).get(name, (False, None))
        if not enabled or command is None:
            return {"ok": False, "result": {"kind": "warn", "text": "지금은 할 수 없는 관리자 일입니다", "sub": "화면의 상태를 확인하세요"}}
        self._credentials = (admin_id, pin)
        try:
            return self._run_menu_action(command)
        finally:
            self._credentials = None

    def _run_menu_action(self, command: Callable[[], Any]) -> Dict[str, Any]:
        """관리자 메뉴 명령이 내는 안내를 판 결과로 모은다."""
        self._admin_notes = []
        try:
            value = command()
        finally:
            notes, self._admin_notes = self._admin_notes or [], None
        return self._action_reply(value, notes)

    def _action_reply(self, value: Any, notes: List[Dict[str, Any]]) -> Dict[str, Any]:
        refusal = next((note for note in reversed(notes) if note["kind"] in {"bad", "warn"}), None)
        if refusal is not None:
            return {"ok": False, "result": {"kind": "warn", "text": refusal["text"]}}
        if isinstance(value, dict) and type(value.get("ok")) is bool:
            return value
        if value is True:
            if notes:
                return {"ok": True, "result": {"kind": "ok", "text": notes[-1]["text"]}}
            return {"ok": True}
        if value is False or (isinstance(value, str) and value):
            return {"ok": False, "result": {"kind": "warn", "text": "처리하지 못했습니다 — 화면의 상태를 확인하세요"}}
        return {"ok": False, "result": {"kind": "idle", "text": "처리 결과를 확인하지 못했습니다", "sub": notes[-1]["text"] if notes else "화면의 상태를 확인하세요"}}

    def closing(self) -> bool:
        """창 X — 지금 on_closing 규칙(저장 중이면 미룸)을 그대로 묻는다. False = 닫기 막음."""
        busy = bool(_attr(self.app, "_completion_lane_busy")) or bool(
            _attr(self.app, "_ui_lane") is not None and self.app._ui_lane.is_busy())
        if busy:
            self.note({"kind": "warn", "text": "완료 처리 중이라 아직 닫지 않았습니다 — 끝난 뒤 다시 닫으세요"})
            return False
        return True

    # 처리 층 쪽에서 부르는 것 ─────────────────────────
    def note(self, note: Dict[str, Any]) -> None:
        if self._admin_notes is not None:
            self._admin_notes.append(note)
            return
        self.notes = (self.notes + [note])[-5:]
        self._push()

    def ask(self, title: str, message: str, yes: str, no: str) -> Optional[bool]:
        if self._answer is not None:
            return False  # 물음 안의 물음 — 그만두기
        lead = message.strip().replace("\n\n", "\n")
        self.sheet = {"kind": "info", "tag": "확인", "title": title, "lead": lead,
                      "modal": True, "cancel": "choose:ask_no",
                      "actions": [{"text": no, "go": "command:choose:ask_no", "quiet": True},
                                  {"text": yes, "go": "command:choose:ask_yes"}]}
        self._answer = self._new_answer()
        self._push()
        try:
            self._wait(self._answer)
            answer = self._answer.get()
        finally:
            self._answer = None
            self.sheet = None
            self._push()
        return answer == "yes"

    def ask_scan(self, title: str, prompt: str) -> Optional[str]:
        self.sheet = {"kind": "info", "tag": "스캔", "title": title, "lead": f"{_first_line(prompt)} — 스캐너로 찍으세요",
                      "modal": True, "cancel": "choose:ask_cancel",
                      "actions": [{"text": "그만두기", "go": "command:choose:ask_cancel", "quiet": True}]}
        self._scan_answer = self._new_answer()
        self._answer = self._scan_answer
        self._push()
        try:
            self._wait(self._scan_answer)
            value = self._scan_answer.get()
        finally:
            self._scan_answer = None
            self._answer = None
            self.sheet = None
            self._push()
        return value[5:] if value.startswith("scan:") else None

    # 안쪽 ──────────────────────────────────────────────
    def _new_answer(self) -> Any:
        root = self.app.root
        return tk.StringVar(master=root, value="") if isinstance(root, tk.Misc) else _Answer()

    def _wait(self, answer: Any) -> None:
        """지금 Tk 대화상자와 같은 기다림 — 이 안에서도 root.after 펌프가 돌아 화면 답(choose)을 받는다."""
        self.app.root.wait_variable(answer)

    def _push(self) -> None:
        if self.bridge is not None:
            try:
                self.bridge.push_state(reason="changed")
            except Exception:
                pass

    def _take_credentials(self, **_kw: Any) -> Optional[Tuple[str, str]]:
        credentials, self._credentials = self._credentials, None  # 한 번만 — 값은 남기지 않음
        if credentials is None:
            self.note({"kind": "warn", "text": "관리자 확인이 다시 필요합니다 — 관리자 ID와 PIN을 다시 넣으세요"})
        return credentials

    def _no_test_item(self, *_args: Any, **_kw: Any) -> None:
        self.note({"kind": "warn", "text": "시험 트레이 품목 고르기는 새 화면에 없습니다 — 관리자에게 알리세요"})
        return None

    def _enter(self, raw: str) -> None:
        """지금 시험(public_scan)과 같은 스캔 문 — 입력 칸에 넣고 process_barcode(빈 글 = 빈 Enter)."""
        entry = self.app.scan_entry
        try:
            entry.delete(0, tk.END)
        except Exception:
            pass
        if raw:
            entry.insert(0, raw)
        self.app.process_barcode()

    def _invoke(self, widget_name: str) -> Dict[str, Any]:
        widget = _attr(self.app, widget_name)
        if widget is None or _widget_enabled(self.app, widget_name) is False:
            return {"ok": False, "result": {"kind": "warn", "text": "지금은 누를 수 없습니다"}}
        return self._run_menu_action(lambda: invoke_button_callback(widget))

    def _menu(self, name: str) -> Dict[str, Any]:
        enabled, command = operations_menu(self.app).get(name, (False, None))
        if not enabled or command is None:
            return {"ok": False, "result": {"kind": "warn", "text": "지금은 할 수 없습니다"}}
        return self._run_menu_action(command)

    def _pane_values(self) -> Dict[str, Any]:
        """한 단계 안 화면 값 — 그 화면이 열렸을 때만 읽는다(파일 읽기가 있는 것)."""
        view = _view(self.app, self.view)
        if view == "start":
            register = None
            if self._registration_name:
                roster = _attr(self.app, "worker_roster")
                candidates = roster.duplicate_workers(self._registration_name) if roster is not None else []
                register = {"name": self._registration_name,
                            "cands": [{"id": row["worker_id"], "label": ca.worker_choice_label(row)}
                                      for row in candidates[:10]]}
            return {"roster": roster_values(self.app), "register": register, "start_error": None}
        if view == "held":
            return self._held_values()
        if view == "progress":
            return {"progress": progress_values(self.app)}
        if view == "f8":
            return {"f8": f8_values(self.app)}
        return {}

    def _held_values(self) -> Dict[str, Any]:
        park = []
        try:
            roster = _attr(self.app, "worker_roster")
            worker_id = str(_attr(self.app, "_selected_roster_id", "") or "")
            entries = self.app._parked_store().scan_for_worker(
                ca.persistent_operator_name(self.app.worker_name),
                tray_size=_attr(self.app, "TRAY_SIZE", 60), strict=True,
                worker_id=worker_id,
                worker_id_aliases=roster.identity_aliases(worker_id) if roster is not None else (),
            )
        except Exception:
            entries = []
        self._park_paths = {}
        for entry in entries:
            path = str(_attr(entry, "path", "") or "")
            park_id = hashlib.sha256(path.encode("utf-8")).hexdigest()[:12]
            self._park_paths[park_id] = path
            park.append({"id": park_id, "item": str(_attr(entry, "problem", "") or _attr(entry, "item_name", "") or "품목 미확인"),
                         "tag": "", "count": int(_attr(entry, "scan_count", 0) or 0), "target": 0, "at": ""})
        restricted = []
        for held in self.app._quarantined_preflight_holds():
            snapshot = held.snapshot
            fields = self.app._parse_new_format_qr(snapshot.master_raw) or {}
            item = str(fields.get("CLC") or "품목 미확인")
            tag = str(fields.get("LBL") or "현품표 미확인")
            count = len(snapshot.items)
            waiting = self.app._is_offline_preflight_hold(snapshot)
            kind, title = ("server_wait", "서버 확인 대기") if waiting else ("quarantine", "사전조회 격리")
            reason = ("회사 서버 연결을 확인하세요" if waiting else
                      self.app._preflight_failure_guidance(snapshot.error_code, held_retry=False)[0])
            if reason == "중앙 PHS=2 확인 실패":
                reason = "현품표 확인이 필요합니다"
            # Only controlled guidance reaches the screen; paths and error text stay private.
            restricted.append({"id": hashlib.sha256(str(held.path).encode("utf-8")).hexdigest()[:12],
                         "item": item, "tag": tag, "count": count, "target": 0,
                         "at": snapshot.created_at, "kind": kind, "restorable": False,
                         "label": f"{item} · {tag} · {count}개", "note": f"{title} — {reason}"})
        total = len(park) + len(restricted)
        shown_restricted = restricted[:50]
        # Both recovery-only kinds remain visible even if they alone exceed the cap.
        for kind in ("quarantine", "server_wait"):
            if not any(row["kind"] == kind for row in shown_restricted):
                missing = next((row for row in restricted if row["kind"] == kind), None)
                if missing is not None:
                    shown_restricted[-1] = missing
        park = park[:50 - len(shown_restricted)] + shown_restricted
        return {"park": park, "held_count": total, "overflow": total > len(park),
                "today": today_values(self.app), "stats": []}

    # 명령 ──────────────────────────────────────────────
    def _cmd_ack(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        if self.view or _view(self.app, None) in {"progress", "f8"}:
            return self._cmd_close(None, {})
        self._enter("")  # 지금 빈 Enter 문 그대로(CA:14727 — 막는 알림 확인 · 담당자 확인이면 안 풀림)
        return {"ok": True}

    def _cmd_choose(self, choice_id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        choice_id = str(choice_id or "")
        if self._answer is not None and choice_id in {"ask_yes", "ask_no", "ask_cancel"}:
            self._answer.set("yes" if choice_id == "ask_yes" else "no" if choice_id == "ask_no" else "cancel")
            return {"ok": True}
        if choice_id == "note_ok":
            self.notes = []
            return {"ok": True}
        if choice_id == "ack":
            return self._cmd_ack(None, {})
        app = self.app
        for index, choice in enumerate(_attr(app, "_inline_scan_choices") or []):
            if CHOICE_IDS.get(str(choice[0]), f"choice-{index}") != choice_id:
                continue
            # 지금 _request_inline_choice 의 choose(CA:14823)와 같은 차례: 선택 지움 → 단추 줄 없앰 → 확인 → 콜백 → 초점
            app._inline_scan_choices = []
            app._inline_choice_on_scan = None
            frame = _attr(app, "_inline_choice_frame")
            if frame is not None:
                frame.destroy()
                app._inline_choice_frame = None
            app._warning_state_presenter().acknowledge()
            choice[1]()
            schedule = _attr(app, "_schedule_focus_return")
            if callable(schedule):
                schedule()
            return {"ok": True}
        return {"ok": False, "result": {"kind": "warn", "text": "그 선택은 이미 지나갔습니다"}}

    def _cmd_exchange(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        return self._menu("exchange")

    def _cmd_undo(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        return self._invoke("undo_button")

    def _cmd_submit(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        return self._invoke("submit_tray_button")

    def _cmd_park(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        return self._invoke("park_button")

    def _cmd_restore(self, park_id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        path = getattr(self, "_park_paths", {}).get(str(park_id or ""))
        if not path:
            return {"ok": False, "result": {"kind": "warn", "text": "보류 목록이 바뀌었습니다 — 다시 고르세요"}}
        self.view = None
        return self._run_menu_action(lambda: self.app.restore_parked_tray(path))

    def _cmd_reset(self, confirmed: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        if confirmed != "confirmed":  # 화면 확인 판에서만(지금 코드엔 확인이 없어 새로 생긴 한 번 확인)
            return {"ok": False, "result": {"kind": "warn", "text": "리셋은 확인 판에서만 합니다"}}
        return self._menu("reset")

    def _cmd_refresh_items(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        return self._menu("refresh")

    def _cmd_resend_completion(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.app._is_preflight_hold_supervisor():
            return {"ok": False, "result": {"kind": "warn", "text": "관리자로 로그인해야 다시 보낼 수 있습니다"}}
        enabled, command = operations_menu(self.app).get("resend_completion", (False, None))
        if not enabled or command is None:
            return {"ok": False, "result": {"kind": "warn", "text": "지금은 할 수 없는 관리자 일입니다", "sub": "화면의 상태를 확인하세요"}}
        return self._run_menu_action(command)

    def _cmd_change_worker(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        return self._invoke("change_worker_button")

    def _cmd_open(self, view: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        if view == "progress":
            self.view = None
            self.app.show_logistics_progress()
        elif view == "held":
            self.view = "held"
        else:
            return {"ok": False, "result": {"kind": "warn", "text": "모르는 화면입니다"}}
        return {"ok": True}

    def _cmd_close(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        self.view = None
        if _attr(self.app, "_progress_visible"):
            self.app._hide_logistics_progress()
        if _attr(self.app, "_phs_label_exchange_panel_open"):
            self.app._close_phs_label_exchange_panel()
        return {"ok": True}

    def _cmd_f8(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        self.view = None
        self.app._on_phs_label_exchange_shortcut()
        return {"ok": True}

    def _cmd_f8_reprint(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        var = _attr(self.app, "phs_label_reprint_confirm_var")
        if var is None:
            return {"ok": False, "result": {"kind": "warn", "text": "다시 인쇄할 교체가 없습니다"}}
        var.set(True)  # 지금 체크(CA:12221) — 실물이 없음을 확인했다는 뜻
        return self._invoke("phs_label_exchange_execute_button")

    def _cmd_start_work(self, label: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        entry = _attr(self.app, "worker_entry")
        if entry is None or not label:
            return {"ok": False, "result": {"kind": "warn", "text": "작업자를 다시 고르세요"}}
        try:
            entry.set(str(label))
        except AttributeError:
            entry.delete(0, tk.END)
            entry.insert(0, str(label))
        if self._registration_name:
            roster = _attr(self.app, "worker_roster")
            candidates = roster.duplicate_workers(self._registration_name) if roster is not None else []
            if any(roster.same_person(row["worker_id"], str(label)) for row in candidates):
                self.app._register_worker_name(self._registration_name, existing_worker_id=str(label))
                self._registration_name = None
            elif str(label) not in self.app._worker_selection_names():
                return {"ok": False, "result": {"kind": "warn", "text": "이름이 바뀌었습니다 — 다시 등록하세요"}}
            else:
                self._registration_name = None
        self.view = None
        return self._run_menu_action(self.app.start_work)

    def _cmd_register_worker(self, _id: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        name = str(args.get("name") or "").strip()
        if not name:
            return {"ok": False, "result": {"kind": "warn", "text": "이름을 넣으세요"}}
        name = ca.normalize_registration_name(name)
        roster = _attr(self.app, "worker_roster")
        candidates = roster.duplicate_workers(name) if roster is not None else []
        existing = str(args.get("existing_worker_id") or "")
        if existing and not any(roster.same_person(row["worker_id"], existing) for row in candidates):
            return {"ok": False, "result": {"kind": "warn", "text": "이름이 바뀌었습니다 — 다시 등록하세요"}}
        if candidates and not existing:
            self._registration_name = name
            return {"ok": True}
        self.app._register_worker_name(name, existing_worker_id=existing)
        self._registration_name = None
        return {"ok": True}

    def _cmd_check_unsettled(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        return self._menu("check_unsettled")

    def _cmd_confirm_master_label(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        return {"ok": False, "result": {"kind": "warn", "text": "원래 현품표 확인은 「함께 보류한 기록 목록」 안에서 합니다"}}

    def _cmd_close_app(self, _id: Any, _args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.closing():
            return {"ok": False}
        if self.bridge is not None:
            self.bridge.request_exit()
        return {"ok": True}


# ── 주인 스레드 진입(셸 host run_app(owner_main=…)) ────────────
class CaStartupRefused(RuntimeError):
    """기존 시작 처리가 앱을 만들지 않고 돌려준 종료 값."""

    def __init__(self, code: Any) -> None:
        super().__init__("Container Audit startup refused")
        self.code = code


def shell_data_dir() -> Path:
    """셸 몫 자료 — 기존 새 화면의 사용자 로컬 앱 자료 위치."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise RuntimeError("SHELL_DATA_UNAVAILABLE")
    base = Path(local)
    data = base / "KMTech" / "ContainerAudit" / "screen"
    from storage_policy import require_prepared_machine_directory
    require_prepared_machine_directory(data)
    return data


def admission_write_guard(op: str, path: Path, kind: str) -> Any:
    """셸의 지역 쓰기 하나 동안만 기존 이적 쓰기 허락을 얻는다."""
    return writer_admission("screen_shell_fileio")


def _check_screen_ready() -> None:
    try:
        raw = (APP_DIR / "shell" / "SHELL-READY-v3.16.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != "a8183b660932778c08ebdf1ee24f137b4c2540a66207850afeff9990bbfb3198":
            raise ValueError("shell ready differs")
        ready = json.loads(raw)
        if ready["version"] != "v3.16.3":
            raise ValueError("shell ready version differs")
        for row in ready["files"]:
            relative = Path(row["path"])
            if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != "shell-v3.16.3":
                raise ValueError("shell ready path differs")
            data = (APP_DIR / "shell" / Path(*relative.parts[1:])).read_bytes()
            if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                raise ValueError("shell ready payload differs")
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ScreenStartupUnavailable("SHELL_READY_FAILED") from error


def _screen_failure_reason(error: Exception) -> str:
    if isinstance(error, ScreenStartupUnavailable):
        return error.reason if error.reason in {
            "WEBVIEW2_MISSING", "SHELL_READY_FAILED", "SHELL_DATA_REFUSED", "SCREEN_START_ERROR",
        } else "SCREEN_START_ERROR"
    data_codes = {"SHELL_DATA_IN_APP_ROOT", "SHELL_DATA_NOT_WRITABLE", "NOT_WRITABLE"}
    if getattr(error, "code", None) in data_codes or any(str(error).startswith(code) for code in data_codes):
        return "SHELL_DATA_REFUSED"
    if isinstance(error, PermissionError):
        return "SHELL_DATA_REFUSED"
    if isinstance(error, ImportError) and (getattr(error, "name", "") or "").split(".")[0] in {
        "webview", "clr", "pythonnet", "clr_loader", "System", "Microsoft",
    }:
        return "WEBVIEW2_MISSING"
    message = str(error).lower()
    if ("webview2" in message or "edgechromium" in message) and any(
        word in message for word in ("runtime", "missing", "not found", "not available")
    ):
        return "WEBVIEW2_MISSING"
    return "SCREEN_START_ERROR"


def _can_fall_back(attempt: ScreenLaunchAttempt) -> bool:
    try:
        return not attempt.windows and not attempt.initial_windows and not attempt.surface_was_seen() and attempt.cleanup_before_fallback()
    except Exception:
        return False  # Unknown cleanup never grants permission to open another UI.


def _write_screen_startup_record(data: Path, record: Dict[str, Any]) -> None:
    # The shell has prepared this user directory. Telemetry never creates roots.
    path = data / "screen-startup.jsonl"
    if path.is_symlink() or (path.exists() and path.stat().st_size >= 256 * 1024):
        return
    with writer_admission("screen_shell_fileio", timeout_seconds=0.0):
        with path.open("ab") as stream:
            stream.write((json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8"))


def _record_screen_startup(data: Optional[Path], event: str, *, error: Any = None,
                           elapsed_ms: int = 0, ready: bool = False,
                           code: Optional[str] = None, cause: Optional[str] = None) -> None:
    if data is None or event not in {"WEBVIEW_START_ENTER", "WEBVIEW_START_RETURN", "WEBVIEW_START_ERROR", "OWNER_ERROR", "BEFORE_EXIT"}:
        return
    name = type(error).__name__ if error is not None else None
    if name is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) is None:
        name = "Exception"
    record = {"event": event, "exception": name, "ms": max(0, int(elapsed_ms)), "ready": bool(ready),
              "code": code if code in {"SHELL_START_FAILED", "SHELL_START_TIMEOUT"} else "OTHER",
              "cause": cause if cause in {"RUNTIME_MISSING", "WEBVIEW_ENV_FAILED", "WEBVIEW_NO_READY", "READY_TIMEOUT", "OWNER_START_FAILED", "OTHER"} else "OTHER"}
    try:
        _write_screen_startup_record(data, record)
    except Exception:
        pass  # Optional telemetry cannot bypass admission or change recovery.




def screen_runner(module: Any) -> Callable[[List[str]], Any]:
    def run(arguments: List[str]) -> Any:
        shell_dir = str(APP_DIR / "shell")
        if shell_dir not in sys.path:
            sys.path.insert(0, shell_dir)
        host = module.CA_SCREEN_HOST
        original_host = dict(host)
        host.pop("exit", None)
        host.pop("error", None)
        attempt = ScreenLaunchAttempt()
        fallback_reason = None
        importing_shell = True
        data = None
        started_at = time.monotonic()
        attempt.startup_observer = lambda event, **fields: _record_screen_startup(data, event, **fields)

        def before_exit(_code: str, deadline_s: float) -> bool:
            bridge = attempt.bridge
            _record_screen_startup(data, "BEFORE_EXIT", error=host.get("error"),
                                   elapsed_ms=int((time.monotonic() - started_at) * 1000),
                                   ready=bool(getattr(bridge, "_startup_ready", False)), code=_code,
                                   cause=getattr(bridge, "_startup_cause", None))
            from runtime_entry import set_gui_state
            set_gui_state("closing")
            from writer_session_fence import close_and_wait_writers
            return close_and_wait_writers(deadline_s)

        try:
            import host as shell_host
            from host import run_app
            importing_shell = False
            _check_screen_ready()
            data = shell_data_dir()
            allowed = getattr(shell_host, "web_allowed", None)
            if allowed is not None:
                with admission_write_guard("web_allowed", data, "udf"):
                    use_web = allowed(data, module.CURRENT_VERSION,
                                      write_guard=admission_write_guard)
                if not use_web:
                    host["requested"] = False
                    return module._run_gui_application(arguments)

            with attempt.observe_host(shell_host):
                result = run_app("rw", data, udf=data / "webview2", root=APP_DIR / "ui", page=PAGE,
                                 title="이적", owner_main=owner_main_for(module, arguments, attempt=attempt),
                                 write_guard=admission_write_guard,
                                 version=module.CURRENT_VERSION, before_exit=before_exit)
            if "error" in host:
                raise host["error"]
            if getattr(attempt, "startup_refused", False) or attempt.surface_was_seen():
                return host.get("exit", result)
            raise ScreenStartupUnavailable("SCREEN_START_ERROR")
        except CaStartupRefused as refused:
            return refused.code
        except Exception as error:
            from writer_session_fence import WriterFenceError
            intentional = (WriterFenceError, module.DataGenerationBlocked, module.DataRootUnavailableError)
            if isinstance(error, intentional) or not _can_fall_back(attempt):
                raise
            fallback_reason = "SHELL_IMPORT_FAILED" if importing_shell or isinstance(error, ImportError) else _screen_failure_reason(error)
        finally:
            owner = attempt.owner_thread
            if owner is None or owner is threading.current_thread() or not owner.is_alive():
                host.clear()
                host.update(original_host)
            host["requested"] = False

        # The owner and all observed forms have ended before restoring the Tk
        # route. Call it directly: gates already ran, and fallback cannot recurse.
        code = fallback_reason if fallback_reason == "SHELL_IMPORT_FAILED" else "SCREEN_UNAVAILABLE_FALLBACK_OLD_" + fallback_reason
        try:
            module._startup_check_observe("note", code)
            module._startup_check_observe("publish")
        except Exception:
            pass  # A failed optional record cannot stop the recovered UI.
        return module._run_gui_application(arguments)

    return run


def owner_main_for(module: Any, arguments: List[str], *, attempt: Optional[ScreenLaunchAttempt] = None) -> Callable[[Any], Any]:
    context = copy_context()

    def owner_main(bridge: Any) -> Any:
        return context.run(run_owner, bridge)

    def run_owner(bridge: Any) -> Any:
        owner_began = time.monotonic()
        if attempt is not None:
            attempt.enter_owner(bridge)
        global ca
        original_module = ca
        ca = module  # Container_Audit.py may have been launched as __main__.
        host = module.CA_SCREEN_HOST
        original_active, original_run = host["active"], host["run"]
        original_attempt = host.get("attempt")
        original_names = [(name, getattr(module, name))
                          for name in ("messagebox", "simpledialog", "filedialog")]
        original_tk = module.tk.Tk
        original_refusal = module._startup_refusal
        started = False

        def run(app: Any) -> None:
            nonlocal started
            started = True
            if attempt is not None:
                attempt.enter_app(app)
            run_on_owner(app, bridge)

        def startup_refusal(*args: Any, **kwargs: Any) -> Any:
            # A refused start has no app: keep its existing notice visible,
            # including the messagebox fallback when reporting is unavailable.
            module.tk.Tk = original_tk
            for name, value in original_names:
                setattr(module, name, value)
            return original_refusal(*args, **kwargs)

        dialogs = ScreenDialogs()
        original_messagebox = dict(original_names)["messagebox"]
        for name in ("showinfo", "showwarning", "showerror"):
            original_notice = getattr(original_messagebox, name, None)
            if not callable(original_notice):
                continue
            screen_notice = getattr(dialogs, name)

            def notice(*args: Any, _original=original_notice, _screen=screen_notice, **kwargs: Any) -> Any:
                if dialogs.processor is not None:
                    return _screen(*args, **kwargs)
                module.tk.Tk = original_tk
                try:
                    return _original(*args, **kwargs)
                finally:
                    module.tk.Tk = _HiddenTk

            setattr(dialogs, name, notice)
        host["active"], host["run"] = True, run
        if attempt is not None:
            host["attempt"] = attempt
        for name, _ in original_names:
            setattr(module, name, dialogs)
        module.tk.Tk = _HiddenTk
        module._startup_refusal = startup_refusal
        try:
            code = module._run_gui_application(arguments)
            if attempt is not None:
                attempt.owner_completed()
            host["exit"] = code  # run_app does not return the owner thread's value.
            if not started:
                if attempt is not None:
                    attempt.startup_refused = True
                bridge.fail_owner(CaStartupRefused(code))
            return code
        except BaseException as error:
            host["error"] = error
            if attempt is not None:
                attempt.record_startup("OWNER_ERROR", error=error, elapsed_ms=int((time.monotonic() - owner_began) * 1000))
            if not started:
                bridge.fail_owner(error)
            return None  # The main thread raises the original error after run_app.
        finally:
            host["active"], host["run"] = original_active, original_run
            if original_attempt is None:
                host.pop("attempt", None)
            else:
                host["attempt"] = original_attempt
            module.tk.Tk = original_tk
            module._startup_refusal = original_refusal
            for name, value in original_names:
                setattr(module, name, value)
            ca = original_module
            if attempt is not None:
                attempt.owner_finished.set()

    return owner_main


def run_on_owner(app: Any, bridge: Any) -> None:
    processor = CaProcessor(app, bridge=bridge, dialogs=ca.messagebox)
    root = app.root

    def pump() -> None:
        if bridge.pump():
            root.after(10, pump)
        else:
            if getattr(bridge, "_startup_failure", None):
                app._screen_exit_waiting = True
            app.on_closing(_confirmed=True)

    try:
        try:
            processor.install()
        except BaseException as error:
            bridge.fail_owner(error)
            raise
        bridge.attach_owner(processor)
        root.after(10, pump)
        app.run()
    finally:
        try:
            processor.shutdown()
        finally:
            if not getattr(bridge, "_startup_failure", None):
                bridge.request_exit()
