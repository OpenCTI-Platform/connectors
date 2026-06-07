from pathlib import Path

CONNECTOR_ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_removes_build_only_git_after_installing_requirements():
    dockerfile = (CONNECTOR_ROOT / "Dockerfile").read_text(encoding="utf-8")

    # Align with the repo's standard Alpine connector image (see
    # templates/external-import/Dockerfile): build-only toolchain (git,
    # build-base) is added before installing requirements and removed after,
    # so it is not left in the final image.
    assert "python:3.12-alpine" in dockerfile
    assert "apk --no-cache add git build-base" in dockerfile
    assert dockerfile.index("pip3 install --no-cache-dir -r requirements.txt") < (
        dockerfile.index("apk del git build-base")
    )


def test_entrypoint_fails_fast_and_executes_python_as_pid_one():
    entrypoint = (CONNECTOR_ROOT / "entrypoint.sh").read_text(encoding="utf-8")

    assert "set -e" in entrypoint
    assert "exec python3 main.py" in entrypoint
