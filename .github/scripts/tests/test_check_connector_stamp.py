import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "check_connector_stamp.py"
spec = importlib.util.spec_from_file_location("check_connector_stamp", SCRIPT)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def make_connector(root, files, path="external-import/sample"):
    connector = root / path
    for name, content in files.items():
        target = connector / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    (connector / "src").mkdir(parents=True, exist_ok=True)
    return connector


def result(root, connector, ubi9=()):
    return check.check_connector(connector, root, set(ubi9))


def test_src_copied_next_to_the_entry_point(tmp_path):
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\nENTRYPOINT ["python", "main.py"]\n'
        },
    )
    [image] = result(tmp_path, connector)
    assert image.covered
    assert image.reason == "stamp at /opt/sample/.connector_version.json"


def test_module_entry_point_reads_its_package_directory(tmp_path):
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/connector/src\nWORKDIR /opt/connector\nCMD ["python", "-m", "src"]\n'
        },
    )
    [image] = result(tmp_path, connector)
    assert image.covered
    assert "/opt/connector/src/.connector_version.json" in image.reason


def test_entrypoint_script_changing_directory(tmp_path):
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["sh", "/entrypoint.sh"]\n',
            "entrypoint.sh": "#!/bin/sh\n# Go to the right directory\ncd /opt/sample\n\n# Start the connector\nexec python3 main.py\n",
        },
    )
    [image] = result(tmp_path, connector)
    assert image.covered


def test_entry_script_copied_alone_misses_the_stamp(tmp_path):
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src/main.py /opt/main.py\nCMD ["python3", "/opt/main.py"]\n'
        },
    )
    [image] = result(tmp_path, connector)
    assert not image.covered
    assert image.reason == "no COPY carries a stamp into the final image"


def test_stamp_restored_after_the_code_directory_is_removed(tmp_path):
    dockerfile = (
        "FROM python:3.12-alpine AS packages\n"
        "COPY --parents src/ pyproject.toml /opt/\n"
        "RUN cd /opt/ && \\\n    pip3 install --no-cache-dir . && \\\n    rm -rf /opt/src\n"
        "FROM packages AS app\n"
        "COPY src/main.py /opt/main.py\n"
        "{restore}"
        'CMD ["python3", "/opt/main.py"]\n'
    )
    connector = make_connector(tmp_path, {"Dockerfile": dockerfile.format(restore="")})
    [image] = result(tmp_path, connector)
    assert not image.covered
    (connector / "Dockerfile").write_text(
        dockerfile.format(restore="COPY .connector_version.jso[n] /opt/\n"),
        encoding="utf-8",
    )
    [image] = result(tmp_path, connector)
    assert image.covered
    assert image.reason == "stamp at /opt/.connector_version.json"


@pytest.mark.parametrize(
    "ignore, covered",
    [
        ("**/.connector_version.json\n", False),
        (".*\nsrc/.*\n", False),
        ("**/.*\n!**/.connector_version.json\n", True),
        ("**/__metadata__\n**/.env\n", True),
    ],
)
def test_dockerignore_rules(tmp_path, ignore, covered):
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\nENTRYPOINT ["python", "main.py"]\n',
            ".dockerignore": ignore,
        },
    )
    [image] = result(tmp_path, connector)
    assert image.covered is covered
    if not covered:
        assert image.reason.startswith("excluded by .dockerignore")


def test_copy_from_a_previous_stage(tmp_path):
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine AS builder\nCOPY src /build/app\n"
                "FROM python:3.12-alpine\nCOPY --from=builder /build/app /opt/app\n"
                'WORKDIR /opt/app\nCMD ["python3", "main.py"]\n'
            )
        },
    )
    [image] = result(tmp_path, connector)
    assert image.covered
    assert image.reason == "stamp at /opt/app/.connector_version.json"


def test_variables_in_paths(tmp_path):
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nENV CONNECTOR_TYPE=EXTERNAL_IMPORT \\\n    CONNECTOR_DIR=/opt/sample\n"
                'COPY src ${CONNECTOR_DIR}\nWORKDIR ${CONNECTOR_DIR}\nENTRYPOINT ["python3", "main.py"]\n'
            )
        },
    )
    [image] = result(tmp_path, connector)
    assert image.covered
    assert image.reason == "stamp at /opt/sample/.connector_version.json"


def test_stamp_too_far_above_the_entry_point(tmp_path):
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nCOPY src /opt\nWORKDIR /opt/a/b/c/d/e\n"
                'CMD ["python3", "/opt/a/b/c/d/e/main.py"]\n'
            )
        },
    )
    [image] = result(tmp_path, connector)
    assert not image.covered
    assert "pycti reads" in image.reason


def test_packaged_connector_ships_the_stamp_in_its_package(tmp_path):
    files = {
        "Dockerfile": (
            "FROM python:3.12-alpine\nCOPY . /opt/build\n"
            "RUN pip install /opt/build && rm -rf /opt/build\n"
            'CMD ["python", "-m", "sample_connector"]\n'
        ),
        "sample_connector/__main__.py": "",
        "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n',
    }
    connector = make_connector(tmp_path, files)
    [image] = result(tmp_path, connector)
    assert image.covered
    (connector / "pyproject.toml").write_text(
        "[project]\nname = 'sample'\n", encoding="utf-8"
    )
    [image] = result(tmp_path, connector)
    assert not image.covered


def test_every_built_variant_is_checked(tmp_path):
    (tmp_path / "Dockerfile_ubi9").write_text(
        'FROM ubi\nARG CONNECTOR_CMD="main.py"\nARG CONNECTOR_WORKDIR="/opt/connector/src"\n'
        "ENV CONNECTOR_CMD=${CONNECTOR_CMD}\nCOPY src /opt/connector/src\nWORKDIR ${CONNECTOR_WORKDIR}\n"
        'CMD ["sh", "-c", "exec python3.12 ${CONNECTOR_CMD}"]\n',
        encoding="utf-8",
    )
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\nENTRYPOINT ["python", "main.py"]\n',
            "Dockerfile_fips": 'FROM python:3.12-alpine\nCOPY src/main.py /opt/sample/main.py\nWORKDIR /opt/sample\nENTRYPOINT ["python", "main.py"]\n',
            ".build.env": "CONNECTOR_WORKDIR=/opt/connector\nCONNECTOR_CMD=src/main.py\n",
        },
    )
    images = {
        image.image: image
        for image in result(tmp_path, connector, ubi9=["external-import/sample"])
    }
    assert set(images) == {
        "external-import/sample",
        "external-import/sample (fips)",
        "external-import/sample (ubi9)",
    }
    assert images["external-import/sample"].covered
    assert not images["external-import/sample (fips)"].covered
    assert images["external-import/sample (ubi9)"].covered


def test_main_reports_and_fails_on_an_uncovered_image(tmp_path, capsys):
    make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\nENTRYPOINT ["python", "main.py"]\n'
        },
        path="stream/good",
    )
    make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src/main.py /opt/main.py\nCMD ["python3", "/opt/main.py"]\n'
        },
        path="stream/bad",
    )
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "ubi9-connectors.json").write_text(
        json.dumps([]), encoding="utf-8"
    )
    assert check.main(["--root", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert (
        "NOT COVERED stream/bad: no COPY carries a stamp into the final image" in output
    )
    assert "1 of 2 connector images carry the stamp" in output
    assert check.main(["--root", str(tmp_path), "stream/good"]) == 0
