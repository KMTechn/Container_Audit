#!/usr/bin/env python
from __future__ import annotations

import json
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageStat


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "OUTLINE_CONTAINER_AUDIT_USER_MANUAL_20260627.md"
ASSET_ROOT = ROOT / "docs" / "assets"
TARGET_DIR = ASSET_ROOT / "container_audit_user_manual_20260630_annotated"
IMAGE_RE = re.compile(r"!\[[^\]]*\]\((assets/[^)]+\.png)\)")


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates = [
        "malgunbd.ttf" if bold else "malgun.ttf",
        "C:/Windows/Fonts/malgunbd.ttf" if bold else "C:/Windows/Fonts/malgun.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _crop_black_margins(image: Image.Image) -> Image.Image:
    rgb = image.convert("RGB")
    width, height = rgb.size
    pixels = rgb.load()
    xs: list[int] = []
    ys: list[int] = []
    step = max(1, min(width, height) // 600)
    for y in range(0, height, step):
        for x in range(0, width, step):
            r, g, b = pixels[x, y]
            if max(r, g, b) > 28:
                xs.append(x)
                ys.append(y)
    if not xs or not ys:
        return rgb
    left = max(0, min(xs) - step * 2)
    top = max(0, min(ys) - step * 2)
    right = min(width, max(xs) + step * 3)
    bottom = min(height, max(ys) + step * 3)
    crop_w = right - left
    crop_h = bottom - top
    if crop_w < width * 0.85 or crop_h < height * 0.85:
        return rgb.crop((left, top, right, bottom))
    return rgb


def _scaled_box(box: tuple[float, float, float, float], width: int, height: int) -> tuple[int, int, int, int]:
    return (
        int(width * box[0]),
        int(height * box[1]),
        int(width * box[2]),
        int(height * box[3]),
    )


def _common_fullscreen_callouts(name: str) -> list[tuple[tuple[float, float, float, float], str]]:
    left_lists = (0.01, 0.10, 0.16, 0.70)
    item_header = (0.38, 0.04, 0.70, 0.12)
    count = (0.43, 0.13, 0.62, 0.26)
    scan_input = (0.17, 0.25, 0.84, 0.33)
    scan_list = (0.17, 0.34, 0.84, 0.82)
    right_status = (0.86, 0.11, 0.99, 0.88)
    bottom_buttons = (0.17, 0.85, 0.84, 0.97)
    tray_image = (0.01, 0.79, 0.16, 0.98)
    if "01_01_launch_login" in name:
        return [
            ((0.42, 0.24, 0.59, 0.54), "프로그램/버전"),
            ((0.42, 0.60, 0.58, 0.67), "작업자 이름"),
            ((0.42, 0.69, 0.58, 0.76), "등록/시작"),
        ]
    if "02_02" in name or "03_03" in name:
        return [
            ((0.01, 0.03, 0.15, 0.07), "작업자"),
            (scan_input, "현품표 QR 입력"),
            (right_status, "현재 상태"),
            (left_lists, "금일/보류 목록"),
        ]
    if "04_master" in name:
        return [
            (item_header, "품목 확인"),
            (count, "0 / 목표수량"),
            (scan_input, "제품 바코드 입력"),
            (left_lists, "금일/보류 목록"),
            (right_status, "작업 상태"),
            (bottom_buttons, "보류/리셋 버튼"),
        ]
    if "05_product" in name:
        return [
            (item_header, "품목 유지"),
            (count, "스캔 수량 증가"),
            (scan_list, "스캔 목록"),
            (bottom_buttons, "보류/취소"),
            (right_status, "상태/시간"),
        ]
    if "07_parked" in name or "08_parked" in name:
        return [
            (left_lists, "보류 트레이 목록"),
            (scan_input, "다음 현품표 대기"),
            (right_status, "대기 상태"),
            (tray_image, "트레이 이미지"),
        ]
    if "10_parked_restored" in name or "11_product" in name:
        return [
            (left_lists, "보류 복원 확인"),
            (item_header, "복원 품목"),
            (count, "복원 수량"),
            (scan_list, "기존 스캔 목록"),
            (bottom_buttons, "계속 작업"),
        ]
    if "12_20" in name or "auto-complete" in name:
        return [
            (item_header, "다음 현품표 대기"),
            (count, "수량 초기화"),
            (left_lists, "금일 완료 반영"),
            (right_status, "작업 상태"),
        ]
    if "undo" in name:
        return [
            (item_header, "현재 품목"),
            (count, "취소 후 수량"),
            (scan_list, "스캔 목록 변경"),
            (bottom_buttons, "마지막 스캔 취소"),
        ]
    if "reset" in name:
        return [
            (scan_input, "현품표 대기"),
            (left_lists, "목록 초기화"),
            (right_status, "대기 상태"),
        ]
    if "restored" in name or "replacement" in name:
        return [
            (item_header, "복구/교체 상태"),
            (count, "수량 확인"),
            (scan_list, "스캔 목록"),
            (bottom_buttons, "주요 버튼"),
        ]
    return [
        (item_header, "현재 품목"),
        (count, "진행 수량"),
        (scan_input, "스캔 입력"),
        (scan_list, "스캔 목록"),
        (right_status, "상태 카드"),
    ]


def _dialog_callouts(name: str, width: int, height: int) -> list[tuple[tuple[int, int, int, int], str]]:
    if width < 700 and height < 300:
        return [
            ((int(width * 0.06), int(height * 0.12), int(width * 0.94), int(height * 0.55)), "확인 내용"),
            ((int(width * 0.08), int(height * 0.60), int(width * 0.92), int(height * 0.94)), "선택 버튼"),
        ]
    if "18-product-exchange" in name:
        return [
            (_scaled_box((0.05, 0.10, 0.95, 0.32), width, height), "교환 수량"),
            (_scaled_box((0.06, 0.35, 0.94, 0.58), width, height), "불량품 스캔"),
            (_scaled_box((0.06, 0.61, 0.94, 0.83), width, height), "양품 스캔"),
            (_scaled_box((0.35, 0.86, 0.95, 0.97), width, height), "완료/닫기"),
        ]
    return [
        (_scaled_box((0.08, 0.16, 0.92, 0.52), width, height), "확인 정보"),
        (_scaled_box((0.12, 0.58, 0.88, 0.90), width, height), "작업 버튼"),
    ]


def _warning_callouts(width: int, height: int) -> list[tuple[tuple[int, int, int, int], str]]:
    return [
        (_scaled_box((0.22, 0.12, 0.78, 0.28), width, height), "경고 제목"),
        (_scaled_box((0.18, 0.36, 0.82, 0.50), width, height), "오류 원인"),
        (_scaled_box((0.42, 0.73, 0.58, 0.86), width, height), "확인 후 복귀"),
    ]


def _callouts_for(name: str, width: int, height: int) -> list[tuple[tuple[int, int, int, int], str]]:
    if name == "00-workflow.png":
        return [
            (_scaled_box((0.05, 0.04, 0.44, 0.20), width, height), "시작/작업자"),
            (_scaled_box((0.18, 0.23, 0.78, 0.54), width, height), "스캔/검증"),
            (_scaled_box((0.20, 0.58, 0.82, 0.83), width, height), "보류/복원"),
            (_scaled_box((0.38, 0.84, 0.84, 0.97), width, height), "완료/전송"),
        ]
    if "warning" in name or "mismatch" in name or "duplicate" in name:
        return _warning_callouts(width, height)
    if width < 1000 or height < 750:
        return _dialog_callouts(name, width, height)
    return [(_scaled_box(box, width, height), text) for box, text in _common_fullscreen_callouts(name)]


def _draw_callouts(image: Image.Image, name: str) -> Image.Image:
    image = image.convert("RGB")
    draw = ImageDraw.Draw(image)
    width, height = image.size
    line = max(4, int(min(width, height) * 0.0045))
    label_font = _font(max(18, int(min(width, height) * 0.024)), bold=True)
    small_font = _font(max(16, int(min(width, height) * 0.018)), bold=True)
    title_font = _font(max(20, int(min(width, height) * 0.026)), bold=True)
    is_warning = "warning" in name or "mismatch" in name or "duplicate" in name
    accent = "#FDE047" if is_warning else "#E11D48"
    label_text = "#713F12" if is_warning else "#9F1239"
    for index, (box, text) in enumerate(_callouts_for(name, width, height), start=1):
        x1, y1, x2, y2 = box
        x1, y1 = max(0, x1), max(0, y1)
        x2, y2 = min(width - 1, x2), min(height - 1, y2)
        draw.rectangle((x1, y1, x2, y2), outline=accent, width=line)
        label = f"{index}. {text}"
        bbox = draw.textbbox((0, 0), label, font=small_font)
        label_w = bbox[2] - bbox[0] + 20
        label_h = bbox[3] - bbox[1] + 14
        lx = min(max(0, x1), max(0, width - label_w - 4))
        ly = y1 - label_h - 4 if y1 - label_h - 4 > 0 else min(height - label_h - 4, y1 + 6)
        draw.rectangle((lx, ly, lx + label_w, ly + label_h), fill="#FFFFFF", outline=accent, width=max(2, line // 2))
        draw.text((lx + 10, ly + 6), label, fill=label_text, font=small_font)
    return image


def _annotate_one(source: Path, target: Path) -> dict[str, object]:
    image = Image.open(source)
    original_size = image.size
    image = _crop_black_margins(image)
    cropped_size = image.size
    annotated = _draw_callouts(image, target.name)
    target.parent.mkdir(parents=True, exist_ok=True)
    annotated.save(target)
    stat = ImageStat.Stat(annotated.convert("RGB").resize((1, 1)))
    return {
        "source": str(source),
        "target": str(target),
        "original_size": list(original_size),
        "target_size": list(cropped_size),
        "mean_rgb": [round(v, 2) for v in stat.mean],
    }


def _make_contact_sheet(image_names: list[str]) -> dict[str, object]:
    selected = [
        name for name in image_names
        if name not in {"00-workflow.png", "20-contact-sheet.png"}
    ][:12]
    thumb_w, thumb_h = 460, 258
    pad = 28
    label_h = 44
    cols = 3
    rows = (len(selected) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * thumb_w + (cols + 1) * pad, rows * (thumb_h + label_h) + (rows + 1) * pad), "#F8FAFC")
    draw = ImageDraw.Draw(sheet)
    font = _font(22, bold=True)
    for idx, name in enumerate(selected):
        src = TARGET_DIR / name
        im = Image.open(src).convert("RGB")
        im.thumbnail((thumb_w, thumb_h), Image.Resampling.LANCZOS)
        row, col = divmod(idx, cols)
        x = pad + col * (thumb_w + pad)
        y = pad + row * (thumb_h + label_h + pad)
        frame = (x, y, x + thumb_w, y + thumb_h)
        draw.rectangle(frame, fill="#E2E8F0", outline="#CBD5E1", width=2)
        px = x + (thumb_w - im.width) // 2
        py = y + (thumb_h - im.height) // 2
        sheet.paste(im, (px, py))
        label = f"{idx + 1:02d}. {name}"
        draw.text((x, y + thumb_h + 10), label[:42], fill="#0F172A", font=font)
    target = TARGET_DIR / "20-contact-sheet.png"
    sheet.save(target)
    return {"target": str(target), "images": selected, "size": list(sheet.size)}


def main() -> int:
    text = DOC.read_text(encoding="utf-8")
    refs = list(dict.fromkeys(IMAGE_RE.findall(text)))
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    output_names: list[str] = []
    for rel in refs:
        source = ROOT / "docs" / rel
        name = Path(rel).name
        target = TARGET_DIR / name
        if name == "20-contact-sheet.png":
            output_names.append(name)
            continue
        rows.append(_annotate_one(source, target))
        output_names.append(name)
    contact = _make_contact_sheet(output_names)
    manifest = {
        "ok": True,
        "document": str(DOC),
        "target_dir": str(TARGET_DIR),
        "source_refs": refs,
        "annotated_count": len(rows),
        "contact_sheet": contact,
        "images": rows,
    }
    manifest_path = TARGET_DIR / "annotation_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "target_dir": str(TARGET_DIR), "annotated_count": len(rows), "contact_sheet": contact["target"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
