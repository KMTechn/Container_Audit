import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

from tests.native_process_fixtures import native_python_executable

from tools.run_test1_exact_artifact import (
    ArtifactIdentityError, launch_exact_artifact, query_process_executable_path, sha256_file,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "nt", reason="OS executable-path attestation requires Windows")
def test_exact_artifact_launch_records_identity_and_blocks_hash_drift(tmp_path):
    executable = tmp_path / "installed" / "python.exe"
    executable.parent.mkdir()
    base_executable = native_python_executable()
    shutil.copy2(base_executable, executable)
    assert sha256_file(executable) == sha256_file(base_executable)
    for library in (*Path(sys.base_prefix).glob("python*.dll"), *Path(sys.base_prefix).glob("vcruntime*.dll")):
        shutil.copy2(library, executable.parent / library.name)
    archive = tmp_path / "release.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.write(executable, "Package/python.exe")
    children = []
    queried = []
    image = [executable]

    def launch(argv, cwd):
        actual = [str(image[0]), *argv[1:]]
        with (tmp_path/f"child-{len(children)}.stdout").open("xb") as stdout, (tmp_path/f"child-{len(children)}.stderr").open("xb") as stderr:
            process = subprocess.Popen(actual, cwd=cwd, stdin=subprocess.PIPE,
                stdout=stdout, stderr=stderr, env=dict(os.environ, PYTHONHOME=sys.base_prefix),
                creationflags=subprocess.CREATE_NO_WINDOW)
        children.append(process)
        return process

    def query_and_release(pid):
        actual = query_process_executable_path(pid)
        queried.append((pid, actual))
        children[-1].stdin.write(b"x")
        children[-1].stdin.flush()
        return actual

    options = dict(archive_path=archive, expected_archive_sha256=sha256_file(archive),
        executable_path=executable, expected_executable_sha256=sha256_file(executable),
        archive_member="Package/python.exe", popen_factory=launch,
        query_process_path=query_and_release,
        application_args=["-B", "-c", "import os,sys,threading; t=threading.Timer(10,lambda:os._exit(9));t.start();sys.stdin.buffer.read(1);t.cancel()"])
    try:
        evidence = tmp_path/"identity.json"
        identity = launch_exact_artifact(**options, evidence_json=evidence)
        recorded = json.loads(evidence.read_text())
        assert identity == recorded
        assert recorded["status"] == "PASS", recorded
        assert recorded["archive"]["sha256"] == sha256_file(archive)
        assert recorded["archive_member"]["matches_installed_executable"] is True
        assert recorded["installed_executable"]["sha256"] == sha256_file(executable)
        assert recorded["process"] == {
            "pid": children[0].pid, "executable_path": str(executable.resolve()),
            "matches_installed_executable": True, "exit_code": 0,
        }
        assert queried[0][0] == children[0].pid
        assert children[0].poll() == 0

        image[0] = base_executable
        with pytest.raises(ArtifactIdentityError, match="OS-reported process executable path"):
            launch_exact_artifact(**options, evidence_json=tmp_path/"wrong-process.json")
        assert queried[-1][1].resolve() == base_executable
        assert children[-1].poll() is not None
        assert json.loads((tmp_path/"wrong-process.json").read_text())["status"] == "BLOCKED"
        with pytest.raises(ArtifactIdentityError, match="archive SHA-256 mismatch"):
            launch_exact_artifact(**dict(options, expected_archive_sha256="0"*64),
                                  evidence_json=tmp_path/"wrong-hash.json")
        assert len(children) == 2, "bad archive was launched"
    finally:
        for process in children:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            process.stdin.close()


@pytest.mark.parametrize("missing", ["--expected-archive-sha256", "--expected-exe-sha256"])
def test_packaged_driver_rejects_missing_identity_before_opening_ui(tmp_path, missing):
    values = {"--archive": "release.zip", "--expected-archive-sha256": "a"*64,
        "--exe": "app.exe", "--expected-exe-sha256": "b"*64,
        "--output-root": str(tmp_path/"evidence"), "--data-root": str(tmp_path/"data"),
        "--worker": "fixture", "--master-label": "fixture"}
    argv = [part for key, value in values.items() if key != missing for part in (key, value)]
    result = subprocess.run([sys.executable,"-B",str(ROOT/"tools/packaged_real_ui_driver.py"),*argv],
                            capture_output=True,text=True,timeout=15)
    assert result.returncode == 2
    assert "the following arguments are required: " + missing in result.stderr
    assert not (tmp_path/"evidence").exists()
    assert not (tmp_path/"data").exists()
