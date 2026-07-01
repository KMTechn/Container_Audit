#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import sys
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANUAL = ROOT / "docs" / "OUTLINE_CONTAINER_AUDIT_USER_MANUAL_20260627.md"
DEFAULT_ASSET_DIR = ROOT / "docs" / "assets" / "container_audit_user_manual_20260627"
DEFAULT_OUTLINE_URL = "https://wiki.kmtecherp.com"
DEFAULT_DOCUMENT_ID = "38dcd747-21d1-456f-852d-c929aa835e03"
DEFAULT_TITLE = "Container_Audit(이적실 프로그램)"
EXPECTED_UNIQUE_IMAGES = 21
UA = "ContainerAuditManualPublisher/20260627"


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _candidate_env_files(explicit: str = "") -> list[Path]:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get("OUTLINE_ENV_FILE"):
        candidates.append(Path(os.environ["OUTLINE_ENV_FILE"]))
    candidates.extend(
        [
            ROOT / ".outline_env",
            ROOT.parent / ".outline_env",
            ROOT.parent.parent / ".outline_env",
            Path.home() / ".outline_env",
            Path("/root/.outline_env"),
        ]
    )
    seen: set[str] = set()
    unique: list[Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            unique.append(candidate)
            seen.add(key)
    return unique


def _load_outline_config(args: argparse.Namespace) -> tuple[str, str, list[str]]:
    env_values: dict[str, str] = {}
    checked: list[str] = []
    for env_file in _candidate_env_files(args.env_file):
        checked.append(str(env_file))
        env_values.update(_load_env_file(env_file))
    outline_url = (
        args.outline_url
        or os.environ.get("OUTLINE_URL")
        or env_values.get("OUTLINE_URL")
        or DEFAULT_OUTLINE_URL
    )
    token = os.environ.get("OUTLINE_API_TOKEN") or env_values.get("OUTLINE_API_TOKEN") or ""
    return outline_url.rstrip("/"), token, checked


def _manual_image_paths(text: str) -> list[str]:
    return re.findall(
        r"!\[[^\]]*\]\((assets/container_audit_user_manual_20260627/[^)\s]+\.png)\)",
        text,
    )


def _outline_attachment_urls(text: str) -> list[str]:
    return re.findall(
        r"!\[[^\]]*\]\((https://wiki\.kmtecherp\.com/api/attachments\.redirect\?id=[^)]+)\)",
        text,
    )


def _build_outline_text(
    manual_path: Path,
    asset_dir: Path,
    attachment_urls: dict[str, str] | None = None,
    expected_unique_images: int = EXPECTED_UNIQUE_IMAGES,
) -> tuple[str, dict[str, Any]]:
    text = manual_path.read_text(encoding="utf-8")
    links = _manual_image_paths(text)
    unique_links = list(dict.fromkeys(links))
    missing = [rel for rel in unique_links if not (asset_dir / Path(rel).name).exists()]
    report: dict[str, Any] = {
        "manual_path": str(manual_path),
        "asset_dir": str(asset_dir),
        "markdown_image_refs": len(links),
        "unique_image_refs": len(unique_links),
        "missing_images": missing,
        "mermaid_block_count": text.count("```mermaid"),
        "workflow_png_refs": text.count("00-workflow.png"),
        "contact_sheet_refs": text.count("20-contact-sheet.png"),
        "remaining_field_approval_phrase_count": text.count("실제 하드웨어 스캐너"),
    }
    if len(unique_links) != expected_unique_images:
        raise RuntimeError(
            f"expected {expected_unique_images} unique images, got {len(unique_links)}"
        )
    if missing:
        raise FileNotFoundError(f"missing manual images: {missing}")
    if report["mermaid_block_count"] < 1:
        raise RuntimeError("manual must include the Mermaid workflow block")
    if report["workflow_png_refs"] < 1:
        raise RuntimeError("manual must include the workflow PNG fallback")
    if report["contact_sheet_refs"] < 1:
        raise RuntimeError("manual must include the contact sheet")
    if report["remaining_field_approval_phrase_count"] < 1:
        raise RuntimeError("manual must keep the remaining field-approval caveat")
    if attachment_urls:
        for rel in unique_links:
            text = text.replace(rel, attachment_urls[rel])
        report.update(
            {
                "outline_attachment_refs": text.count("/api/attachments.redirect"),
                "relative_image_refs_after_replace": text.count(
                    "assets/container_audit_user_manual_20260627/"
                ),
            }
        )
    return text, report


class OutlineClient:
    def __init__(self, base_url: str, token: str) -> None:
        if not token:
            raise RuntimeError("OUTLINE_API_TOKEN is required for publish mode")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.session = requests.Session()
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": UA,
        }

    def api(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}/api/{method}",
            headers=self.headers,
            json=payload,
            timeout=60,
        )
        if not response.ok:
            raise RuntimeError(f"{method} HTTP {response.status_code}: {response.text[:500]}")
        data = response.json()
        if data.get("ok") is False:
            raise RuntimeError(f"{method} not ok: {data}")
        return data

    def upload_image(self, document_id: str, path: Path) -> str:
        content_type = mimetypes.guess_type(path.name)[0] or "image/png"
        created = self.api(
            "attachments.create",
            {
                "name": path.name,
                "contentType": content_type,
                "size": path.stat().st_size,
                "documentId": document_id,
            },
        )["data"]
        upload_url = created["uploadUrl"]
        if upload_url.startswith("/"):
            upload_url = self.base_url + upload_url
        attachment_url = created["attachment"]["url"]
        if attachment_url.startswith("/"):
            attachment_url = self.base_url + attachment_url
        with path.open("rb") as image_file:
            uploaded = self.session.post(
                upload_url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/json,*/*",
                    "User-Agent": UA,
                },
                data=created.get("form") or {},
                files={"file": (path.name, image_file, content_type)},
                timeout=180,
            )
        if not uploaded.ok:
            raise RuntimeError(
                f"upload failed {path.name}: HTTP {uploaded.status_code}: {uploaded.text[:500]}"
            )
        return attachment_url


def _extract_doc(api_response: dict[str, Any]) -> dict[str, Any]:
    data = api_response.get("data") or {}
    if isinstance(data, dict) and "document" in data:
        return data["document"]
    return data if isinstance(data, dict) else {}


def _write_report(path: str, report: dict[str, Any]) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Publish the Container_Audit user manual to Outline")
    parser.add_argument("--manual", default=str(DEFAULT_MANUAL))
    parser.add_argument("--asset-dir", default=str(DEFAULT_ASSET_DIR))
    parser.add_argument("--outline-url", default="")
    parser.add_argument("--document-id", default=DEFAULT_DOCUMENT_ID)
    parser.add_argument("--title", default=DEFAULT_TITLE)
    parser.add_argument("--env-file", default="")
    parser.add_argument("--report-path", default="")
    parser.add_argument("--expected-unique-images", type=int, default=EXPECTED_UNIQUE_IMAGES)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--reuse-existing-attachments",
        action="store_true",
        help="Reuse the current document's attachment URLs instead of creating new attachments.",
    )
    args = parser.parse_args(argv)

    manual_path = Path(args.manual)
    asset_dir = Path(args.asset_dir)
    outline_url, token, env_files_checked = _load_outline_config(args)

    try:
        if args.dry_run:
            _, report = _build_outline_text(
                manual_path,
                asset_dir,
                expected_unique_images=args.expected_unique_images,
            )
            report.update(
                {
                    "status": "PASS",
                    "mode": "dry-run",
                    "outline_url": outline_url,
                    "document_id": args.document_id,
                    "title": args.title,
                    "token_present": bool(token),
                    "env_files_checked": env_files_checked,
                }
            )
            _write_report(args.report_path, report)
            print(json.dumps(report, ensure_ascii=False, sort_keys=True))
            return 0

        client = OutlineClient(outline_url, token)
        source_text = manual_path.read_text(encoding="utf-8")
        unique_links = list(dict.fromkeys(_manual_image_paths(source_text)))
        if args.reuse_existing_attachments:
            current_doc = _extract_doc(client.api("documents.info", {"id": args.document_id}))
            existing_urls = _outline_attachment_urls(current_doc.get("text") or "")
            if len(existing_urls) < len(unique_links):
                raise RuntimeError(
                    f"not enough existing attachment URLs to reuse: {len(existing_urls)} < {len(unique_links)}"
                )
            attachment_urls = dict(zip(unique_links, existing_urls[: len(unique_links)]))
        else:
            attachment_urls = {
                rel: client.upload_image(args.document_id, asset_dir / Path(rel).name)
                for rel in unique_links
            }
        outline_text, local_report = _build_outline_text(
            manual_path,
            asset_dir,
            attachment_urls,
            expected_unique_images=args.expected_unique_images,
        )
        client.api(
            "documents.update",
            {
                "id": args.document_id,
                "title": args.title,
                "text": outline_text,
                "editMode": "replace",
                "publish": True,
            },
        )
        info = client.api("documents.info", {"id": args.document_id})
        doc = _extract_doc(info)
        doc_text = doc.get("text") or ""
        doc_url = doc.get("url") or ""
        if doc_url.startswith("/"):
            doc_url = outline_url + doc_url
        report = {
            **local_report,
            "status": "PASS",
            "mode": "publish",
            "outline_url": doc_url,
            "document_id": args.document_id,
            "unique_images_uploaded": len(attachment_urls),
            "reused_existing_attachments": bool(args.reuse_existing_attachments),
            "document_markdown_image_refs": doc_text.count("!["),
            "document_attachment_refs": doc_text.count("/api/attachments.redirect"),
            "document_relative_image_refs": doc_text.count(
                "assets/container_audit_user_manual_20260627/"
            ),
            "document_mermaid_block_count": doc_text.count("```mermaid"),
            "document_text_length": len(doc_text),
        }
        required = {
            "document_markdown_image_refs": len(unique_links),
            "document_attachment_refs": len(unique_links),
            "document_relative_image_refs": 0,
        }
        for key, expected in required.items():
            if report[key] != expected:
                report["status"] = "FAIL"
                raise RuntimeError(f"{key} expected {expected}, got {report[key]}")
        if report["document_mermaid_block_count"] < 1:
            report["status"] = "FAIL"
            raise RuntimeError("published document does not contain the Mermaid workflow block")
        _write_report(args.report_path, report)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        report = {
            "status": "FAIL",
            "error": str(exc),
            "mode": "dry-run" if args.dry_run else "publish",
            "outline_url": outline_url,
            "document_id": args.document_id,
            "token_present": bool(token),
            "env_files_checked": env_files_checked,
        }
        _write_report(args.report_path, report)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
