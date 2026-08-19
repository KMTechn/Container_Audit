import subprocess

import pytest

from tools.read_release_qualification_tag import (
    parse_annotated_tag_object,
    read_release_qualification,
)


TAG = "v2.0.65"
COMMIT = "1" * 40
TAG_OBJECT = "2" * 40


def _raw_tag(message: bytes, *, commit: str = COMMIT) -> bytes:
    return (
        f"object {commit}\ntype commit\ntag {TAG}\n"
        "tagger Release Test <release@example.invalid> 1 +0000\n\n"
    ).encode("ascii") + message


def _canonical_message() -> bytes:
    return f"Release {TAG}\n".encode("ascii")


def test_parser_accepts_only_canonical_prebuild_final_identity_message():
    identity = parse_annotated_tag_object(
        _raw_tag(_canonical_message()),
        expected_tag=TAG,
        tag_object_sha=TAG_OBJECT,
        peeled_commit_sha=COMMIT,
    )

    assert identity.tag_object_sha == TAG_OBJECT
    assert identity.peeled_commit_sha == COMMIT
    assert identity.message == f"Release {TAG}"


@pytest.mark.parametrize(
    "message",
    [
        _canonical_message() + b"Extra: forbidden\n",
        _canonical_message() + b"\nQualified-ZIP-SHA256: " + b"a" * 64 + b"\n",
        _canonical_message().replace(b"Release", b"release"),
        _canonical_message().rstrip(b"\n"),
        _canonical_message().replace(b"\n", b"\r\n"),
    ],
)
def test_parser_rejects_hash_bearing_extra_or_malformed_identity_message(message):
    with pytest.raises(ValueError, match="exact canonical FINAL"):
        parse_annotated_tag_object(
            _raw_tag(message),
            expected_tag=TAG,
            tag_object_sha=TAG_OBJECT,
            peeled_commit_sha=COMMIT,
        )


def test_parser_rejects_noncanonical_or_differently_peeled_tag_headers():
    with pytest.raises(ValueError, match="headers are not canonical"):
        parse_annotated_tag_object(
            _raw_tag(_canonical_message()).replace(
                b"type commit\n", b"type commit\nencoding UTF-8\n"
            ),
            expected_tag=TAG,
            tag_object_sha=TAG_OBJECT,
            peeled_commit_sha=COMMIT,
        )

    with pytest.raises(ValueError, match="differs from its peeled commit"):
        parse_annotated_tag_object(
            _raw_tag(_canonical_message()),
            expected_tag=TAG,
            tag_object_sha=TAG_OBJECT,
            peeled_commit_sha="3" * 40,
        )


def test_reader_binds_real_tag_object_peel_and_checked_out_head(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()

    def git(*arguments, input_bytes=None):
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            input=input_bytes,
            check=True,
            capture_output=True,
        ).stdout.decode("ascii").strip()

    git("init", "-q")
    git("config", "user.email", "release@example.invalid")
    git("config", "user.name", "Release Test")
    (repository / "fixture.txt").write_text("fixture\n", encoding="ascii")
    git("add", "fixture.txt")
    git("commit", "-q", "-m", "fixture")
    commit = git("rev-parse", "HEAD")
    raw_tag = _raw_tag(_canonical_message(), commit=commit)
    tag_object = git("mktag", input_bytes=raw_tag)
    git("update-ref", f"refs/tags/{TAG}", tag_object)

    qualification = read_release_qualification(
        repository,
        tag_ref=f"refs/tags/{TAG}",
        expected_tag=TAG,
    )

    assert qualification.tag_object_sha == tag_object
    assert qualification.peeled_commit_sha == commit
