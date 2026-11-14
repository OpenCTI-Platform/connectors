import importlib.util
import json
import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "check_connector_stamp.py"
WORKFLOW = (
    Path(__file__).resolve().parents[2] / "workflows" / "ci-check-connector-stamp.yml"
)
spec = importlib.util.spec_from_file_location("check_connector_stamp", SCRIPT)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

ALPINE_SRC = 'FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\nENTRYPOINT ["python", "main.py"]\n'


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


def single(root, files):
    [image] = result(root, make_connector(root, files))
    return image


def test_src_copied_next_to_the_entry_point(tmp_path):
    image = single(tmp_path, {"Dockerfile": ALPINE_SRC})
    assert image.covered
    assert image.reason == "stamp at /opt/sample/.connector_version.json"


def test_module_entry_point_reads_its_package_directory(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/connector/src\nWORKDIR /opt/connector\nCMD ["python", "-m", "src"]\n',
            "src/__main__.py": "",
        },
    )
    assert image.covered
    assert "/opt/connector/src/.connector_version.json" in image.reason


def test_module_file_reads_the_directory_of_the_file(tmp_path):
    # `-m src.main` runs src/main.py: its directory is src/, not src/main/.
    dockerfile = (
        "FROM python:3.12-alpine\nCOPY src /opt/connector/src\n"
        "COPY .connector_version.json /opt/connector/src/main/\n"
        'WORKDIR /opt/a/b/c/d\nCMD ["python", "-m", "src.main"]\n'
    )
    files = {
        "Dockerfile": dockerfile,
        "src/main.py": "",
        ".dockerignore": "src/.connector_version.json\n",
    }
    image = single(tmp_path, files)
    assert not image.covered
    assert (
        image.reason
        == "not supported: module src.main is not a file of the image model"
    )
    (tmp_path / "external-import/sample/Dockerfile").write_text(
        dockerfile.replace(
            "WORKDIR /opt/a/b/c/d",
            "ENV PYTHONPATH=/opt/connector\nWORKDIR /opt/a/b/c/d",
        ),
        encoding="utf-8",
    )
    [image] = result(tmp_path, tmp_path / "external-import/sample")
    assert not image.covered
    assert image.reason.startswith(
        "stamp at /opt/connector/src/main/.connector_version.json, pycti reads"
    )


def test_entrypoint_script_changing_directory(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["sh", "/entrypoint.sh"]\n',
            "entrypoint.sh": "#!/bin/sh\n# Go to the right directory\ncd /opt/sample\n\n# Start the connector\nexec python3 main.py\n",
        },
    )
    assert image.covered


def test_entrypoint_script_run_directly_with_a_conditional_without_cd(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
            "entrypoint.sh": (
                "#!/bin/sh\nset -eu\ncd /opt/sample || exit 1\n"
                "if ! command -v helper >/dev/null 2>&1; then\n  echo 'missing helper' >&2\n  exit 1\nfi\n"
                "helper_start\nexec python3 main.py\n"
            ),
        },
    )
    assert image.covered
    assert image.reason == "stamp at /opt/sample/.connector_version.json"


@pytest.mark.parametrize(
    "script, reason",
    [
        (
            '#!/bin/sh\nif [ -n "$X" ]; then cd /opt/sample; fi\npython3 main.py\n',
            "working directory changed by a conditional 'cd'",
        ),
        (
            "#!/bin/sh\ncd /opt/sample\nif true; then python3 main.py; fi\n",
            "the connector started inside a conditional or a loop",
        ),
        (
            "#!/bin/sh\ncd $CONNECTOR_HOME\npython3 main.py\n",
            "'cd' target '$CONNECTOR_HOME' uses a variable",
        ),
        ("#!/bin/sh\n. /opt/env.sh\npython3 main.py\n", "'.' in the entry script"),
        (
            '#!/bin/sh\ncd /opt/sample\nexec "$@"\n',
            "start command '$@' uses a variable",
        ),
        (
            "#!/bin/sh\ncd /opt/sample\nexit 0\npython3 main.py\n",
            "the entry script never starts python",
        ),
        (
            "#!/bin/sh\ncat <<EOF\nhello\nEOF\npython3 main.py\n",
            "a here-document in a shell script",
        ),
        ("cd /opt/sample\npython3 main.py\n", "has no interpreter line"),
    ],
)
def test_entry_scripts_outside_the_model_are_reported(tmp_path, script, reason):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nWORKDIR /opt/sample\nENTRYPOINT ["/entrypoint.sh"]\n',
            "entrypoint.sh": script,
        },
    )
    assert not image.covered
    assert image.reason.startswith("not supported: ")
    assert reason in image.reason


def test_script_carried_by_a_directory_copy_is_read(tmp_path):
    # Copilot review of 21:40 UTC: a script inside a copied directory is followed.
    dockerfile = 'FROM python:3.12-alpine\nCOPY src /opt/app\nWORKDIR /opt/app\nENTRYPOINT ["sh", "/opt/app/entrypoint.sh"]\n'
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": dockerfile,
            "src/entrypoint.sh": "#!/bin/sh\ncd /opt/app/a/b/c/d/e\npython3 main.py\n",
        },
    )
    [image] = result(tmp_path, connector)
    assert not image.covered
    assert (
        image.reason
        == "stamp at /opt/app/.connector_version.json, pycti reads ['/opt/app/a/b/c/d/e']"
    )
    (connector / "src/entrypoint.sh").write_text(
        "#!/bin/sh\ncd /opt/app\npython3 main.py\n", encoding="utf-8"
    )
    [image] = result(tmp_path, connector)
    assert image.covered


@pytest.mark.parametrize(
    "entrypoint, reason",
    [
        (
            '["sh", "/start.sh"]',
            "shell script /start.sh is not a file of the image model",
        ),
        ('["/start.sh"]', "entry point /start.sh is not a file of the image model"),
        (
            '["my-connector"]',
            "entry point 'my-connector' is not a file of the image model",
        ),
    ],
)
def test_unresolved_entry_points_are_reported(tmp_path, entrypoint, reason):
    image = single(
        tmp_path,
        {
            "Dockerfile": f"FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\nENTRYPOINT {entrypoint}\n"
        },
    )
    assert not image.covered
    assert image.reason == f"not supported: {reason}"


def test_entry_script_copied_alone_misses_the_stamp(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src/main.py /opt/main.py\nCMD ["python3", "/opt/main.py"]\n',
            "src/main.py": "",
        },
    )
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
    files = {
        "Dockerfile": dockerfile.format(restore=""),
        "src/main.py": "",
        "pyproject.toml": "[project]\nname = 'sample'\n",
    }
    connector = make_connector(tmp_path, files)
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
    "command, covered",
    [
        # Copilot review of 21:40 UTC: a wildcard deletes the copied directory.
        ("rm -rf /opt/*", False),
        ("cd /opt && rm -rf ./*", False),
        ("rm -rf /opt/s?c", False),
        ("rm -rf /opt/[st]rc", False),
        # A shell wildcard never matches the leading dot of the stamp.
        ("rm -rf /opt/src/*", True),
        ("rm -f /opt/src/*.json", True),
        ("rm -f /opt/src/.connector_version.*", False),
        ("sh -c 'rm -rf /opt/src'", False),
        ("find /opt -name '*.json' -delete", False),
        ("find /opt -type d -name __pycache__ -exec rm -rf {} +", True),
        ("find /opt -type f -name '*.pyc' -delete", True),
        ("find /opt -mtime +1 -delete", False),
        ("mv /opt/src /srv/src", False),
        ("unlink /opt/src/.connector_version.json", False),
        ("rm -rf /var/cache/apk/*", True),
    ],
)
def test_deletions_after_the_copy(tmp_path, command, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                f"FROM python:3.12-alpine\nCOPY src /opt/src\nRUN {command}\n"
                'COPY src/main.py /opt/src/main.py\nCMD ["python3", "/opt/src/main.py"]\n'
            ),
            "src/main.py": "",
        },
    )
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf $BUILD_DIR",
        "rm -rf `cat dirs`",
        "find /opt -type f | xargs rm -f",
        "find /opt -exec sh -c 'rm {}' \\;",
    ],
)
def test_deletions_with_unknown_operands_are_reported(tmp_path, command):
    image = single(
        tmp_path,
        {
            "Dockerfile": f'FROM python:3.12-alpine\nCOPY src /opt/src\nRUN {command}\nWORKDIR /opt/src\nCMD ["python3", "main.py"]\n'
        },
    )
    assert not image.covered
    assert image.reason.startswith("not supported: ")


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
    image = single(tmp_path, {"Dockerfile": ALPINE_SRC, ".dockerignore": ignore})
    assert image.covered is covered
    if not covered:
        assert image.reason.startswith("excluded by .dockerignore")


def test_dockerfile_specific_ignore_file_wins(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": ALPINE_SRC,
            ".dockerignore": "",
            "Dockerfile.dockerignore": "**/.connector_version.json\n",
        },
    )
    assert not image.covered
    assert image.reason.startswith("excluded by .dockerignore")


def test_copy_exclude_flag(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY --exclude=**/*.json src /opt/sample\nWORKDIR /opt/sample\nCMD ["python3", "main.py"]\n'
        },
    )
    assert not image.covered


def test_copy_from_a_previous_stage(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine AS builder\nCOPY src /build/app\n"
                "FROM python:3.12-alpine\nCOPY --from=builder /build/app /opt/app\n"
                'WORKDIR /opt/app\nCMD ["python3", "main.py"]\n'
            )
        },
    )
    assert image.covered
    assert image.reason == "stamp at /opt/app/.connector_version.json"


def test_variables_in_paths(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nENV CONNECTOR_TYPE=EXTERNAL_IMPORT \\\n    CONNECTOR_DIR=/opt/sample\n"
                'COPY src ${CONNECTOR_DIR}\nWORKDIR ${CONNECTOR_DIR}\nENTRYPOINT ["python3", "main.py"]\n'
            )
        },
    )
    assert image.covered
    assert image.reason == "stamp at /opt/sample/.connector_version.json"


@pytest.mark.parametrize(
    "dockerfile, reason",
    [
        (
            'FROM python:3.12-alpine\nCOPY src ${APP_DIR}\nCMD ["python3", "/opt/main.py"]\n',
            "COPY destination '${APP_DIR}' uses a variable",
        ),
        (
            'FROM python:3.12-alpine\nRUN <<EOF\nrm -rf /opt\nEOF\nCMD ["python3", "/opt/main.py"]\n',
            "a here-document in RUN",
        ),
        (
            'FROM my/base\nCOPY src app\nCMD ["python3", "app/main.py"]\n',
            "relative to an unknown working directory",
        ),
        ("FROM python:3.12-alpine\nCOPY src /opt/sample\n", "no CMD or ENTRYPOINT"),
    ],
)
def test_dockerfiles_outside_the_model_are_reported(tmp_path, dockerfile, reason):
    image = single(tmp_path, {"Dockerfile": dockerfile})
    assert not image.covered
    assert image.reason.startswith("not supported: ")
    assert reason in image.reason


def test_arg_values_do_not_reach_the_running_container(tmp_path):
    # The shell of the start command only sees ENV values.
    dockerfile = (
        "FROM python:3.12-alpine\nARG APP=/opt/sample\nCOPY src /opt/sample\n"
        'CMD ["sh", "-c", "cd $APP && exec python3 main.py"]\n'
    )
    image = single(tmp_path, {"Dockerfile": dockerfile})
    assert not image.covered
    assert "'$APP' uses a variable" in image.reason
    (tmp_path / "external-import/sample/Dockerfile").write_text(
        dockerfile.replace("ARG APP", "ENV APP"), encoding="utf-8"
    )
    [image] = result(tmp_path, tmp_path / "external-import/sample")
    assert image.covered


def test_stamp_too_far_above_the_entry_point(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nCOPY src /opt\nWORKDIR /opt/a/b/c/d/e\n"
                'CMD ["python3", "/opt/a/b/c/d/e/main.py"]\n'
            )
        },
    )
    assert not image.covered
    assert "pycti reads" in image.reason


def test_stamp_file_name_is_checked(tmp_path):
    # Copilot review of 21:40 UTC: pycti only opens .connector_version.json.
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY .connector_version.json /opt/version.json\nCMD ["python3", "/opt/main.py"]\n'
        },
    )
    assert not image.covered
    assert (
        image.reason
        == "stamp copied as /opt/version.json: pycti only reads .connector_version.json"
    )


PACKAGED_DOCKERFILE = (
    "FROM python:3.12-alpine\nCOPY . /opt/build\n"
    "RUN pip install /opt/build && rm -rf /opt/build\n"
    'CMD ["python", "-m", "sample_connector"]\n'
)


def packaged(root, packaging, dockerfile=PACKAGED_DOCKERFILE, ignore=None):
    files = {"Dockerfile": dockerfile, "sample_connector/__main__.py": "", **packaging}
    if ignore is not None:
        files[".dockerignore"] = ignore
    return single(root, files)


def test_packaged_connector_ships_the_stamp_in_its_package(tmp_path):
    image = packaged(
        tmp_path,
        {
            "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
        },
    )
    assert image.covered
    assert (
        image.reason
        == "stamp at /<site-packages>/sample_connector/.connector_version.json"
    )


@pytest.mark.parametrize(
    "packaging",
    [
        {"pyproject.toml": "[project]\nname = 'sample'\n"},
        # Copilot review of 21:40 UTC: a mention of the file name is not a declaration.
        {
            "pyproject.toml": '[tool.setuptools.package-data]\n# sample_connector = [".connector_version.json"]\n'
        },
        {
            "pyproject.toml": '[tool.setuptools.package-data]\nother_package = [".connector_version.json"]\n'
        },
        {
            "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = ["*.json"]\n'
        },
        {
            "pyproject.toml": (
                '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
                '[tool.setuptools.exclude-package-data]\nsample_connector = [".connector_*"]\n'
            )
        },
        {
            "pyproject.toml": (
                '[tool.setuptools.packages.find]\nexclude = ["sample_*"]\n'
                '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
            )
        },
    ],
)
def test_package_data_that_does_not_select_the_stamp(tmp_path, packaging):
    image = packaged(tmp_path, packaging)
    assert not image.covered


@pytest.mark.parametrize(
    "packaging",
    [
        {
            "pyproject.toml": '[tool.setuptools.package-data]\n"*" = [".connector_version.json"]\n'
        },
        {
            "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = ["**/.connector_*.json"]\n'
        },
        {
            "setup.cfg": "[options.package_data]\nsample_connector =\n    .connector_version.json\n    *.txt\n"
        },
    ],
)
def test_package_data_that_selects_the_stamp(tmp_path, packaging):
    assert packaged(tmp_path, packaging).covered


@pytest.mark.parametrize(
    "packaging, reason",
    [
        (
            {
                "pyproject.toml": '[build-system]\nbuild-backend = "hatchling.build"\n',
                "setup.cfg": "[options.package_data]\nsample_connector = .connector_version.json\n",
            },
            "package data of the build backend hatchling.build",
        ),
        (
            {
                "pyproject.toml": "[project]\nname = 'sample'\n",
                "setup.py": "from setuptools import setup\nsetup(package_data={'sample_connector': ['.connector_version.json']})\n",
            },
            "package data declared in setup.py",
        ),
        (
            {
                "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n',
                "MANIFEST.in": "global-exclude *.json\n",
            },
            "exclusions of MANIFEST.in",
        ),
    ],
)
def test_packaging_outside_the_model_is_reported(tmp_path, packaging, reason):
    image = packaged(tmp_path, packaging)
    assert not image.covered
    assert image.reason == f"not supported: {reason}"


def test_installed_stamp_needs_the_source_stamp(tmp_path):
    # Copilot review of 21:40 UTC: no installed stamp when the source stamp never reached pip.
    pyproject = {
        "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
    }
    image = packaged(
        tmp_path / "ignored", pyproject, ignore="**/.connector_version.json\n"
    )
    assert not image.covered
    assert image.reason.startswith("excluded by .dockerignore")
    removed = PACKAGED_DOCKERFILE.replace(
        "RUN pip install",
        "RUN rm /opt/build/sample_connector/.connector_version.json && pip install",
    )
    image = packaged(tmp_path / "removed", pyproject, dockerfile=removed)
    assert not image.covered
    editable = PACKAGED_DOCKERFILE.replace(
        "pip install /opt/build", "pip install -e /opt/build"
    )
    image = packaged(tmp_path / "editable", pyproject, dockerfile=editable)
    assert not image.covered


def test_every_built_variant_is_checked(tmp_path):
    (tmp_path / "Dockerfile_ubi9").write_text(
        'FROM registry.access.redhat.com/ubi9/ubi-minimal\nARG CONNECTOR_CMD="main.py"\nARG CONNECTOR_WORKDIR="/opt/connector/src"\n'
        "ENV CONNECTOR_CMD=${CONNECTOR_CMD}\nCOPY src /opt/connector/src\nWORKDIR ${CONNECTOR_WORKDIR}\n"
        'CMD ["sh", "-c", "exec python3.12 ${CONNECTOR_CMD}"]\n',
        encoding="utf-8",
    )
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": ALPINE_SRC,
            "Dockerfile_fips": 'FROM python:3.12-alpine\nCOPY src/main.py /opt/sample/main.py\nWORKDIR /opt/sample\nENTRYPOINT ["python", "main.py"]\n',
            ".build.env": 'CONNECTOR_WORKDIR="/opt/connector"\nCONNECTOR_CMD="-m src"\n',
            "src/__main__.py": "",
            "src/main.py": "",
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
    assert (
        images["external-import/sample (ubi9)"].reason
        == "stamp at /opt/connector/src/.connector_version.json"
    )


@pytest.mark.parametrize(
    "command, covered",
    [
        ('["python3", "-u", "-X", "dev", "main.py"]', True),
        ('["python3", "-c", "import main"]', True),
        ("python3 main.py", True),
        ('["env", "PYTHONUNBUFFERED=1", "python3", "main.py"]', True),
        ('["python3", "-I", "-m", "main"]', False),
    ],
)
def test_python_command_lines(tmp_path, command, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": f"FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\nCMD {command}\n",
            "src/main.py": "",
        },
    )
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # A script of the image run or sourced by RUN deletes for real.
        ("sh /opt/src/clean.sh", False),
        ("/opt/src/clean.sh", False),
        (". /opt/src/clean.sh", False),
        ("cd /opt && . /opt/src/goto.sh && rm -rf src", True),
        (". /opt/venv/bin/activate && cd src && rm -rf data", False),
    ],
)
def test_scripts_run_by_a_build_step(tmp_path, run, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                f"FROM python:3.12-alpine\nCOPY src /opt/src\nRUN {run}\n"
                'COPY src/main.py /opt/src/main.py\nCMD ["python3", "/opt/src/main.py"]\n'
            ),
            "src/main.py": "",
            "src/clean.sh": "#!/bin/sh\nrm -rf /opt/src\n",
            "src/goto.sh": "cd /tmp\n",
        },
    )
    assert image.covered is covered, image.reason


def test_entry_script_handing_over_to_another_script(tmp_path):
    files = {
        "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
        "entrypoint.sh": "#!/bin/sh\nexec /opt/sample/run.sh\n",
        "src/run.sh": "#!/bin/sh\ncd /opt/sample && exec python3 main.py\n",
    }
    assert single(tmp_path, files).covered


def test_every_python_process_of_the_entry_script_needs_the_stamp(tmp_path):
    # Which python process is the connector is not known: each must read a stamp.
    files = {
        "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
        "entrypoint.sh": "#!/bin/sh\npython3 /usr/local/share/warmup.py\ncd /opt/sample\nexec python3 main.py\n",
    }
    image = single(tmp_path, files)
    assert not image.covered
    assert image.reason.startswith("python process 1 of 2: stamp at /opt/sample/")
    (tmp_path / "external-import/sample/entrypoint.sh").write_text(
        "#!/bin/sh\ncd /opt/sample\npython3 warmup.py\nexec python3 main.py\nrm -rf /opt/sample\n",
        encoding="utf-8",
    )
    [image] = result(tmp_path, tmp_path / "external-import/sample")
    assert image.covered


def test_script_started_without_exec_is_followed(tmp_path):
    files = {
        "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
        "entrypoint.sh": "#!/bin/sh\ncd /opt/sample\n./run.sh\n",
        "src/run.sh": "#!/bin/sh\npython3 main.py\n",
    }
    assert single(tmp_path, files).covered
    (tmp_path / "external-import/sample/src/run.sh").write_text(
        "#!/bin/sh\nrm -rf /opt/sample/.connector_version.json\npython3 main.py\n",
        encoding="utf-8",
    )
    [image] = result(tmp_path, tmp_path / "external-import/sample")
    assert not image.covered


def test_operators_written_without_spaces(tmp_path):
    # shlex returns ");" as one token: the subshell must still close.
    files = {
        "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
        "entrypoint.sh": "#!/bin/sh\nVERSION=$(cat /opt/sample/VERSION);cd /opt/sample&&exec python3 main.py\n",
    }
    assert single(tmp_path, files).covered


def test_assignment_prefix_reaches_python(tmp_path):
    files = {
        "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/app/src\nWORKDIR /tmp\nCMD ["sh", "-c", "PYTHONPATH=/opt/app exec python3 -m src"]\n',
        "src/__main__.py": "",
    }
    image = single(tmp_path, files)
    assert image.covered
    assert image.reason == "stamp at /opt/app/src/.connector_version.json"


def test_shell_form_entrypoint_ignores_cmd(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nENTRYPOINT python3 /opt/sample/main.py\nCMD ["python3", "/elsewhere/main.py"]\n'
        },
    )
    assert image.covered


def test_workflow_watches_every_file_the_check_reads():
    # Copilot review of 21:40 UTC: a change to any of these files must run the check.
    text = WORKFLOW.read_text(encoding="utf-8")
    sections = re.split(r"^  (push|pull_request|merge_group):", text, flags=re.M)
    filters = {sections[i]: sections[i + 1] for i in range(1, len(sections) - 1, 2)}
    for event in ("push", "pull_request"):
        paths = set(re.findall(r"^\s+- '([^']+)'", filters[event], flags=re.M))
        for name in check.WATCHED_FILES:
            assert f"**/{name}" in paths, f"{event} does not watch {name}"
        for name in (
            "**/Dockerfile",
            "**/Dockerfile_fips",
            check.UBI9_DOCKERFILE,
            check.UBI9_CONNECTORS,
        ):
            assert name in paths, f"{event} does not watch {name}"


def test_main_reports_and_fails_on_an_uncovered_image(tmp_path, capsys):
    make_connector(tmp_path, {"Dockerfile": ALPINE_SRC}, path="stream/good")
    make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src/main.py /opt/main.py\nCMD ["python3", "/opt/main.py"]\n',
            "src/main.py": "",
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
