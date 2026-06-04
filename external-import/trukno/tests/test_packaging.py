from pathlib import Path

CONNECTOR_ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_removes_build_only_git_after_installing_requirements():
    dockerfile = (CONNECTOR_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "apt-get install -y --no-install-recommends git libmagic1" in dockerfile
    assert dockerfile.index("pip install --no-cache-dir -r requirements.txt") < (
        dockerfile.index("apt-get purge -y --auto-remove git")
    )


def test_entrypoint_fails_fast_and_executes_python_as_pid_one():
    entrypoint = (CONNECTOR_ROOT / "entrypoint.sh").read_text(encoding="utf-8")

    assert "set -e" in entrypoint
    assert "exec python3 main.py" in entrypoint
