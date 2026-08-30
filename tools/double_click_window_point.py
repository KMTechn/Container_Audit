from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import time


DISPLAY3_BOUNDS = (3840, 326, 6400, 1766)
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--hwnd", type=int, required=True)
    parser.add_argument("--x", type=int, required=True)
    parser.add_argument("--y", type=int, required=True)
    args = parser.parse_args()

    actual_pid = wintypes.DWORD()
    ctypes.windll.user32.GetWindowThreadProcessId(
        wintypes.HWND(args.hwnd), ctypes.byref(actual_pid)
    )
    if actual_pid.value != args.pid:
        raise SystemExit("window PID mismatch")
    rect = wintypes.RECT()
    if not ctypes.windll.user32.GetWindowRect(
        wintypes.HWND(args.hwnd), ctypes.byref(rect)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    screen_x = rect.left + args.x
    screen_y = rect.top + args.y
    if not (rect.left <= screen_x < rect.right and rect.top <= screen_y < rect.bottom):
        raise SystemExit("point is outside exact window")
    dl, dt, dr, db = DISPLAY3_BOUNDS
    if not (dl <= screen_x < dr and dt <= screen_y < db):
        raise SystemExit("point is outside DISPLAY3")
    if not ctypes.windll.user32.SetCursorPos(screen_x, screen_y):
        raise ctypes.WinError(ctypes.get_last_error())
    for _ in range(2):
        ctypes.windll.user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        ctypes.windll.user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
        time.sleep(0.08)
    print(
        f"pid={args.pid} hwnd={args.hwnd} "
        f"window_point={args.x},{args.y} screen_point={screen_x},{screen_y}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
