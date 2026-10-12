"""이적 새 화면으로 띄우기 — 셸 host(v3.8) owner_main 꼴. 지금 Tk 창 대신 pywebview 창 하나에 ui/app/ca/index.html.

w9uiflow1014, APP-SCREENS-1013 ③. 처리 층 · 지금 진입(Container_Audit.py main())은 그대로 두는 새 진입이다.
설치 판에서 어느 진입을 바로 가기로 둘지는 주인 레인(w9firstupd)이 정한다.
  python ca_screen_main.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent


def shell_data_dir() -> Path:
    """셸 몫 자료(events.jsonl · journal.jsonl · WebView2 프로필) — 사용자 로컬 앱 자료 아래."""
    base = Path(os.environ.get("LOCALAPPDATA") or APP_DIR)
    return base / "KMTech" / "ContainerAudit" / "screen"


def main(argv: list[str] | None = None) -> int:
    sys.path.insert(0, str(APP_DIR / "shell"))
    from host import run_app
    from ca_screen_bridge import PAGE, owner_main

    # 셸 v3.8: 묶음 꼭대기(ui/)를 http 뿌리로 — ../frame.js · ../../core/tokens.css 가 닿게
    return run_app("rw", shell_data_dir(), root=APP_DIR / "ui", page=PAGE, title="이적", owner_main=owner_main)


if __name__ == "__main__":
    raise SystemExit(main())
