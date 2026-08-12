#!/usr/bin/env python
"""Read the canonical create-once frozen-release identity from an annotated tag."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


MAX_TAG_OBJECT_BYTES = 16 * 1024
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
RELEASE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")


@dataclass(frozen=True)
class ReleaseTagIdentity:
    tag: str
    tag_object_sha: str
    peeled_commit_sha: str
    message: str


def _git(repository: Path, *arguments: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        capture_output=True,
        text=not binary,
    )
    if completed.returncode != 0:
        stderr = (
            completed.stderr.decode("utf-8", errors="replace")
            if binary
            else completed.stderr
        )
        raise ValueError(f"git {' '.join(arguments[:2])} failed: {stderr.strip()}")
    return completed.stdout


def _lower_git_object(value: str, *, label: str) -> str:
    normalized = value.strip()
    if not GIT_OBJECT_RE.fullmatch(normalized):
        raise ValueError(f"{label} is not an exact lowercase Git object id")
    return normalized


def parse_annotated_tag_object(
    raw_object: bytes,
    *,
    expected_tag: str,
    tag_object_sha: str,
    peeled_commit_sha: str,
) -> ReleaseTagIdentity:
    """Parse the exact unsigned annotated tag created before release-mode build."""

    if not RELEASE_TAG_RE.fullmatch(expected_tag):
        raise ValueError("expected tag must be exact vMAJOR.MINOR.PATCH")
    tag_object_sha = _lower_git_object(tag_object_sha, label="tag object")
    peeled_commit_sha = _lower_git_object(peeled_commit_sha, label="peeled commit")
    if len(raw_object) > MAX_TAG_OBJECT_BYTES:
        raise ValueError("annotated tag object exceeds the bounded parser size")

    header, separator, message = raw_object.partition(b"\n\n")
    header_lines = header.split(b"\n")
    expected_tag_bytes = expected_tag.encode("ascii")
    if (
        not separator
        or len(header_lines) != 4
        or not re.fullmatch(rb"object ([0-9a-f]{40})", header_lines[0])
        or header_lines[1] != b"type commit"
        or header_lines[2] != b"tag " + expected_tag_bytes
        or not re.fullmatch(rb"tagger [^\r\n]+", header_lines[3])
    ):
        raise ValueError("annotated tag object headers are not canonical")

    target_sha = header_lines[0].split(b" ", 1)[1].decode("ascii")
    if target_sha != peeled_commit_sha:
        raise ValueError("annotated tag object target differs from its peeled commit")

    expected_message = b"Release " + expected_tag_bytes + b"\n"
    if message != expected_message:
        raise ValueError(
            "annotated tag message is not the exact canonical FINAL intended identity"
        )

    return ReleaseTagIdentity(
        tag=expected_tag,
        tag_object_sha=tag_object_sha,
        peeled_commit_sha=peeled_commit_sha,
        message=expected_message[:-1].decode("ascii"),
    )


def read_release_qualification(
    repository: Path,
    *,
    tag_ref: str,
    expected_tag: str,
    require_head_match: bool = True,
) -> ReleaseTagIdentity:
    repository = repository.resolve()
    if tag_ref != f"refs/tags/{expected_tag}":
        raise ValueError("tag ref must exactly match the expected release tag")
    object_type = str(_git(repository, "cat-file", "-t", tag_ref)).strip()
    if object_type != "tag":
        raise ValueError("release ref must be an annotated tag object")
    object_size_text = str(_git(repository, "cat-file", "-s", tag_ref)).strip()
    if not re.fullmatch(r"[0-9]+", object_size_text):
        raise ValueError("annotated tag object size is malformed")
    if int(object_size_text) > MAX_TAG_OBJECT_BYTES:
        raise ValueError("annotated tag object exceeds the bounded parser size")

    tag_object_sha = _lower_git_object(
        str(_git(repository, "rev-parse", "--verify", tag_ref)),
        label="tag object",
    )
    peeled_commit_sha = _lower_git_object(
        str(_git(repository, "rev-parse", "--verify", f"{tag_ref}^{{commit}}")),
        label="peeled commit",
    )
    if require_head_match:
        head_commit_sha = _lower_git_object(
            str(_git(repository, "rev-parse", "--verify", "HEAD^{commit}")),
            label="checked-out HEAD",
        )
        if head_commit_sha != peeled_commit_sha:
            raise ValueError("checked-out HEAD differs from the annotated tag peel")
    raw_object = _git(repository, "cat-file", "tag", tag_ref, binary=True)
    if not isinstance(raw_object, bytes):  # pragma: no cover - typing guard
        raise TypeError("raw tag object capture must be bytes")
    return parse_annotated_tag_object(
        raw_object,
        expected_tag=expected_tag,
        tag_object_sha=tag_object_sha,
        peeled_commit_sha=peeled_commit_sha,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--tag-ref", required=True)
    parser.add_argument("--expected-tag", required=True)
    args = parser.parse_args(argv)
    try:
        identity = read_release_qualification(
            args.repository,
            tag_ref=args.tag_ref,
            expected_tag=args.expected_tag,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"release_tag_identity=FAIL reason={exc}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(identity), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
