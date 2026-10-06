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
# A wrapper that deletes the stamp, then runs the program it stands for.
ENV_WRAPPER = (
    '#!/bin/sh\nrm -f /opt/sample/.connector_version.json\nexec /usr/bin/env "$@"\n'
)


def make_connector(root, files, path="external-import/sample"):
    connector = root / path
    for name, content in {"src/main.py": "", **files}.items():
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
                "if ! command -v unogenerator_start >/dev/null 2>&1; then\n  echo 'missing listener' >&2\n  exit 1\nfi\n"
                "unogenerator_start\nexec python3 main.py\n"
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
            "src/a/b/c/d/e/main.py": "",
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
        # Copilot review of 23:37 UTC: quoted or escaped punctuation is an argument.
        ("find /opt/src \\( -name '*.json' \\) -delete", False),
        ("find /opt/src -name '*.json' -exec rm {} \\;", False),
        ("find /opt/src -name '*.pyc' -exec rm {} \\; && echo 'done; ok'", True),
        # Copilot review of 23:37 UTC: find -exec operands are deleted too.
        (
            "find /tmp -maxdepth 0 -exec rm -f /opt/src/.connector_version.json \\;",
            False,
        ),
        ("find /opt/src -name '*.json' -exec sed -i s/a/b/ {} +", False),
        ("find /opt/src -type f -exec chmod +r {} +", True),
        # Copilot review of 23:37 UTC: truncation and rewriting by redirection.
        (": > /opt/src/.connector_version.json", False),
        ("echo '{}' >> /opt/src/.connector_version.json", False),
        ("cd /opt/src && printf x > .connector_version.json", False),
        ("echo ready > /tmp/ready && ls /opt/src >/dev/null 2>&1", True),
        # Copilot review of 23:37 UTC: commands the model does not interpret.
        ("cp /dev/null /opt/src/.connector_version.json", False),
        ("truncate -s 0 /opt/src/.connector_version.json", False),
        (
            "python -c 'import os; os.unlink(\"/opt/src/.connector_version.json\")'",
            False,
        ),
        ("rsync -a --delete /tmp/empty/ /opt/src/", False),
        ("chmod 600 /opt/src/.connector_version.json", False),
        ("chmod -R a+rX /opt/src && chown -R 1000 /opt/src", True),
        ("cat /opt/src/.connector_version.json && ls -la /opt/src", True),
        ("python -m compileall /opt/src", True),
        # Programs working on their working directory without naming it.
        ("cd /opt/src && git clean -fdx", False),
        ("cd /opt/src && make clean", False),
        # A program whose effect on the files is not known is reported.
        ("cd /tmp && npm prune", False),
        # Copilot review of 00:11 UTC: each command sees the variables the
        # preceding ones left, with the shell quoting rules.
        ('export APP=/opt/src && rm -f "$APP/.connector_version.json"', False),
        ("APP=/opt/src; rm -rf $APP", False),
        ("APP=/opt/src; echo '$APP' && rm -rf /tmp/$APP", True),
        ("FILES='/tmp/a /opt/src/.connector_version.json'; rm -f $FILES", False),
        ("FILES='/tmp/a /opt/src/.connector_version.json'; rm -f \"$FILES\"", True),
        # Copilot review of 00:11 UTC: a quoted relative stamp name in code.
        (
            "cd /opt/src && python3 -c 'import os; os.unlink(\".connector_version.json\")'",
            False,
        ),
        # Python code run at build time is reported, whatever it does, unless audited.
        ("cd /tmp && python3 -c 'print(\".connector_version.json\")'", False),
        ("python3 -c 'import re; re.compile(\"^/opt/[a-z]+$\")'", False),
        ("python3 -c \"import shutil; shutil.rmtree('$TARGET/src')\"", False),
        # Copilot review of 00:11 UTC: mv replaces its destination.
        ("touch /tmp/empty && mv /tmp/empty /opt/src/.connector_version.json", False),
        (
            "mkdir /tmp/x && touch /tmp/x/.connector_version.json && mv /tmp/x/.connector_version.json /opt/src/",
            False,
        ),
        ("touch /tmp/empty && mv -t /opt/src /tmp/.connector_version.json", False),
        ("touch /tmp/empty && mv /tmp/empty /tmp/other", True),
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


@pytest.mark.parametrize(
    "instructions, covered",
    [
        ("COPY --chmod=0755 src /opt/sample", True),
        ("COPY --chmod=0700 src /opt/sample", False),
        ("COPY --chmod=go-r src /opt/sample", False),
        ("COPY src /opt/sample\nVOLUME /opt/sample", False),
        ('COPY src /opt/sample\nVOLUME ["/data"]', True),
        # Copilot review of 00:11 UTC: an unreadable copy still replaces the destination.
        (
            "COPY src /opt/sample\nCOPY --chmod=000 src/.connector_version.json /opt/sample/.connector_version.json",
            False,
        ),
        ("COPY src /opt/sample\nCOPY --chmod=000 src /opt/sample", False),
        (
            "COPY src /opt/sample\nCOPY --chmod=000 --exclude=*.json src /opt/sample",
            True,
        ),
        # Copilot review of 00:11 UTC: content the model does not know replaces the destination.
        (
            "COPY src /opt/sample\nCOPY --from=python:3.12-alpine /etc/passwd /opt/sample/.connector_version.json",
            False,
        ),
        (
            "COPY src /opt/sample\nADD https://example.com/stamp.json /opt/sample/.connector_version.json",
            False,
        ),
        ("COPY src /opt/sample\nADD payload.tar /opt/sample/", False),
        (
            "COPY src /opt/sample\nCOPY --from=python:3.12-alpine /usr/bin/env /usr/local/bin/env",
            True,
        ),
    ],
)
def test_permissions_and_volumes(tmp_path, instructions, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": f'FROM python:3.12-alpine\n{instructions}\nWORKDIR /opt/sample\nCMD ["python3", "main.py"]\n',
            "payload.tar": "",
        },
    )
    assert image.covered is covered, image.reason


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
                "FROM python:3.12-alpine\nCOPY src /opt\nCOPY src/main.py /opt/a/b/c/d/e/\nWORKDIR /opt/a/b/c/d/e\n"
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
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY .connector_version.json /opt/version.json\nCOPY src/main.py /opt/\nCMD ["python3", "/opt/main.py"]\n'
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


def packaged(root, packaging, dockerfile=PACKAGED_DOCKERFILE, ignore=None, init=True):
    files = {"Dockerfile": dockerfile, "sample_connector/__main__.py": "", **packaging}
    if init:
        files["sample_connector/__init__.py"] = ""
    if ignore is not None:
        files[".dockerignore"] = ignore
    return single(root, files)


@pytest.mark.parametrize(
    "find, covered, reason",
    [
        # Copilot review of 23:37 UTC: without __init__.py the directory is a
        # namespace package, which only namespace discovery installs.
        ('[tool.setuptools.packages.find]\nwhere = ["."]\n', True, None),
        (
            "[tool.setuptools.packages.find]\nnamespaces = false\n",
            False,
            "not supported: module sample_connector is not a file of the image model",
        ),
        (
            "",
            False,
            "not supported: automatic discovery of sample_connector, a directory without __init__.py",
        ),
    ],
)
def test_namespace_package_discovery(tmp_path, find, covered, reason):
    data = '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
    image = packaged(tmp_path, {"pyproject.toml": find + data}, init=False)
    assert image.covered is covered, image.reason
    if reason:
        assert image.reason == reason


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
        # Copilot review of 01:56 UTC: explicit modules turn package discovery off.
        {
            "pyproject.toml": (
                '[tool.setuptools]\npy-modules = ["main"]\n'
                '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
            )
        },
        {
            "setup.cfg": (
                "[options]\npy_modules = main\n"
                "[options.package_data]\nsample_connector = .connector_version.json\n"
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
            "packaging declared in setup.py",
        ),
        (
            # Copilot review of 23:37 UTC: setup() can disable package discovery.
            {
                "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n',
                "setup.py": "from setuptools import setup\nsetup(packages=[])\n",
            },
            "packaging declared in setup.py",
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


def test_scripts_naming_the_stamp_are_taken_as_rewriting_it(tmp_path):
    # The code of a helper script is read like a command line.
    files = {
        "Dockerfile": (
            "FROM python:3.12-alpine\nCOPY src /opt/src\nRUN python3 /opt/src/clean.py\n"
            'CMD ["python3", "/opt/src/main.py"]\n'
        ),
        "src/clean.py": 'import os\nos.remove("/opt/src/.connector_version.json")\n',
    }
    assert not single(tmp_path / "build", files).covered
    files["Dockerfile"] = (
        "FROM python:3.12-alpine\nCOPY src /opt/src\nCOPY entrypoint.sh /\n"
        'ENTRYPOINT ["/entrypoint.sh"]\n'
    )
    files["entrypoint.sh"] = (
        "#!/bin/sh\n: > /opt/src/.connector_version.json\nexec python3 /opt/src/main.py\n"
    )
    assert not single(tmp_path / "start", files).covered


def test_python_script_rewritten_by_a_build_step_is_reported(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nCOPY src /opt/src\nRUN sed -i s/a/b/ /opt/src/main.py\n"
                'CMD ["python3", "/opt/src/main.py"]\n'
            )
        },
    )
    assert image.reason == (
        "not supported: 'sed' is not a command the model knows the effects of on the image files"
    )


@pytest.mark.parametrize(
    "source, covered",
    [
        # Copilot review of 23:37 UTC: COPY --from reads from the root of the stage.
        ("payload", False),
        ("build/payload", True),
        ("/build/payload", True),
    ],
)
def test_copy_from_sources_are_read_from_the_stage_root(tmp_path, source, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine AS builder\nWORKDIR /build\nCOPY src payload\n"
                f"FROM python:3.12-alpine\nCOPY --from=builder {source} /opt/app\n"
                'WORKDIR /opt/app\nCMD ["python3", "main.py"]\n'
            )
        },
    )
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "instructions, covered",
    [
        # Copilot review of 00:37 UTC: venv --clear empties its directory.
        ("RUN python3 -m venv --clear --without-pip /opt/src", False),
        ("RUN python3 -m venv /opt/venv", True),
        # Copilot review of 00:37 UTC: a variable set in a branch is no longer known.
        (
            'ENV APP=/opt/src\nRUN if false; then APP=/tmp; fi; rm -f "$APP/.connector_version.json"',
            False,
        ),
        ("ENV APP=/opt/src\nRUN true || export APP=/tmp; rm -f $APP/x", False),
        ('ENV APP=/opt/src\nRUN APP=/tmp; rm -f "$APP/.connector_version.json"', True),
        # Copilot review of 00:37 UTC: python modules and code run at build time.
        ("RUN python3 -m clean_stamp", False),
        ("RUN python3 -m compileall /opt/src", True),
        # Copilot review of 00:37 UTC: pip options that write a file.
        (
            "RUN pip install --report /opt/src/.connector_version.json -r /opt/src/requirements.txt",
            False,
        ),
        ("RUN pip install --log=/opt/src/.connector_version.json requests", False),
        (
            "RUN pip install --no-cache-dir --log /tmp/pip.log -r /opt/src/requirements.txt",
            True,
        ),
        # Copilot review of 00:37 UTC: one ENV expands with the values before it.
        (
            'ENV APP=/opt/src\nENV APP=/tmp CLEAN=$APP\nRUN rm -f "$CLEAN/.connector_version.json"',
            False,
        ),
        (
            'ENV APP=/opt/src\nENV APP=/tmp\nENV CLEAN=$APP\nRUN rm -f "$CLEAN/.connector_version.json"',
            True,
        ),
        # Closed world: package managers, but not when they install below another root.
        ("RUN apk add --no-cache git && apt-get install -y curl", True),
        ("RUN apk add --root /opt/src git", False),
        ("RUN wget -O /opt/src/.connector_version.json https://example.com/x", False),
        ("RUN wget -P /tmp https://example.com/.connector_version.json", True),
        (
            "RUN curl -fsSL -o /opt/src/.connector_version.json https://example.com/x",
            False,
        ),
        # Copilot review of 01:21 UTC: the commands of a substitution run too.
        ('RUN echo "$(rm -f /opt/src/.connector_version.json)"', False),
        ("RUN echo $(rm -f /opt/src/.connector_version.json)", False),
        ('RUN UNUSED="$(rm -f /opt/src/.connector_version.json)"', False),
        ('RUN VERSION="$(cat /opt/src/main.py)" && echo "$VERSION $((1 + 2))"', True),
        ("RUN echo `rm -f /opt/src/.connector_version.json`", False),
        (
            "RUN for name in $(rm -f /opt/src/.connector_version.json); do :; done",
            False,
        ),
        ('RUN sh -c "echo $(date) > /tmp/built"', True),
        # Copilot review of 01:56 UTC: a variable the model no longer follows
        # takes no default.
        (
            'ENV APP=/opt/src\nRUN if false; then APP=/tmp; fi; rm -f "${APP:-/tmp}/.connector_version.json"',
            False,
        ),
        (
            'RUN if false; then APP=/opt/src; fi; rm -f "${APP:-/tmp}/.connector_version.json"',
            False,
        ),
        (
            'RUN for APP in /opt/src; do rm -f "${APP:-/tmp}/.connector_version.json"; done',
            False,
        ),
        ('RUN rm -f "${APP:-/tmp}/.connector_version.json"', True),
        # A for loop sets its variable.
        (
            'ENV APP=/tmp\nRUN for APP in /opt/src; do rm -f "$APP/.connector_version.json"; done',
            False,
        ),
        ("RUN cat <(rm -f /opt/src/.connector_version.json)", False),
        # Copilot review of 01:21 UTC: case arms, eval and a script read from stdin.
        ("RUN case x in x) rm -f /opt/src/.connector_version.json;; esac", False),
        ("RUN eval 'rm -f /opt/src/.connector_version.json'", False),
        ("RUN echo 'rm -f /opt/src/.connector_version.json' | sh", False),
        ("RUN sh < /opt/src/main.py", False),
        # Copilot review of 01:21 UTC: a directory needs its search permission.
        ("RUN chmod 644 /opt/src", False),
        ("RUN chmod 744 /opt/src", False),
        ("RUN chmod -R 644 /opt/src", False),
        ("RUN chmod 755 /opt/src && chmod 644 /opt/src/main.py", True),
        # Copilot review of 01:21 UTC: target directory options written attached.
        ("RUN mv -t/opt/src /tmp/.connector_version.json", False),
        ("RUN mv --target-directory=/opt/src /tmp/.connector_version.json", False),
        ("RUN mv -T /tmp/new /opt/src", False),
        ("RUN mv /tmp/new /opt/src", True),
        ("RUN ln -sft/opt/src /tmp/.connector_version.json", False),
        # Copilot review of 01:56 UTC: downloader options are a closed set.
        ("RUN curl --config /tmp/curlrc https://example.com/x", False),
        (
            "RUN wget --save-cookies /opt/src/.connector_version.json https://example.com/x",
            False,
        ),
        (
            "RUN echo 'output = /opt/src/.connector_version.json' > /root/.curlrc && curl https://example.com/x",
            False,
        ),
        ("RUN curl -fsSLo /tmp/x https://example.com/x", True),
        ("RUN wget -qO- https://example.com/x > /tmp/x", True),
        # Copilot review of 01:56 UTC: bash expands braces.
        ("RUN bash -c 'rm -rf /opt/{src,other}'", False),
        ("RUN rm -rf /opt/{src,other}", False),
        ("RUN find /opt/src -name '*.pyc' -exec echo {} +", True),
        # Copilot review of 02:24 UTC: an arithmetic expansion may hold a
        # command substitution; a sourced file the model does not know may do
        # anything; chmod wildcards relative to the working directory.
        (
            "RUN echo $(( $(rm -f /opt/src/.connector_version.json; echo 1) ))",
            False,
        ),
        (
            "RUN printf '%s\\n' 'rm -f /opt/src/.connector_version.json' > /tmp/clean.sh && . /tmp/clean.sh",
            False,
        ),
        ("WORKDIR /opt/src\nRUN chmod 000 .connector_*.json", False),
        ("WORKDIR /opt/src\nRUN chmod 644 *.py", True),
        # A function runs where it is called, under a name it may shadow.
        (
            "RUN cat() { rm -f .connector_version.json; }; cd /opt/src; cat main.py",
            False,
        ),
        ("RUN function clean { rm -rf /opt/src; }; clean", False),
        # bash: GLOBIGNORE makes wildcards match a leading dot; IFS changes
        # word splitting.
        ("RUN GLOBIGNORE=x; rm -rf /opt/src/*", False),
        ("RUN IFS=_; D=/opt_src; rm -rf $D", False),
        (
            'ENV APP=/tmp\nRUN printf -vAPP %s /opt/src; rm -f "$APP/.connector_version.json"',
            False,
        ),
        # Copilot review of 01:21 UTC: printf -v sets a variable.
        (
            'ENV APP=/tmp\nRUN printf -v APP %s /opt/src; rm -f "$APP/.connector_version.json"',
            False,
        ),
    ],
)
def test_build_steps(tmp_path, instructions, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                f"FROM python:3.12-alpine\nCOPY src /opt/src\n{instructions}\n"
                'COPY src/main.py /opt/src/main.py\nCMD ["python3", "/opt/src/main.py"]\n'
            )
        },
    )
    assert image.covered is covered, image.reason


def test_audited_build_scripts_only(tmp_path):
    # A build-time script runs only when its exact text was reviewed.
    audited = (
        Path(__file__).resolve().parents[3]
        / "internal-import-file/import-file-stix/src/stixmarx_warmup.py"
    )
    files = {
        "Dockerfile": (
            "FROM python:3.12-alpine\nCOPY src /opt/src\nRUN python3 /opt/src/warmup.py\n"
            'CMD ["python3", "/opt/src/main.py"]\n'
        ),
        "src/warmup.py": audited.read_text(encoding="utf-8"),
    }
    assert single(tmp_path / "audited", files).covered
    files[
        "src/warmup.py"
    ] += "\nimport os\nos.remove('/opt/src/.connector_version.json')\n"
    image = single(tmp_path / "changed", files)
    assert image.reason.startswith(
        "not supported: build-time script /opt/src/warmup.py is not an audited script"
    )


def test_installed_package_deleted_by_its_native_path(tmp_path):
    # Copilot review of 00:37 UTC: the installed packages also have their real path.
    pyproject = {
        "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
    }
    deleted = PACKAGED_DOCKERFILE.replace(
        "&& rm -rf /opt/build",
        "&& rm -rf /opt/build && rm -f /usr/local/lib/python3.12/site-packages/sample_connector/.connector_version.json",
    )
    assert not packaged(tmp_path / "file", pyproject, dockerfile=deleted).covered
    wildcard = PACKAGED_DOCKERFILE.replace(
        "&& rm -rf /opt/build",
        "&& rm -rf /opt/build /usr/local/lib/python3*/site-packages/sample_*",
    )
    assert not packaged(tmp_path / "glob", pyproject, dockerfile=wildcard).covered
    # Copilot review of 00:37 UTC: python -S does not import the installed packages.
    no_site = PACKAGED_DOCKERFILE.replace('"python", "-m"', '"python", "-S", "-m"')
    image = packaged(tmp_path / "nosite", pyproject, dockerfile=no_site)
    assert (
        image.reason
        == "not supported: module sample_connector is not a file of the image model"
    )


@pytest.mark.parametrize(
    "command, covered",
    [
        # Copilot review of 00:37 UTC: env -u removes the variable for the command.
        ('["sh", "-c", "env -u PYTHONPATH python3 -m src"]', False),
        ('["env", "-u", "PYTHONPATH", "python3", "-m", "src"]', False),
        ('["sh", "-c", "python3 -m src"]', True),
    ],
)
def test_env_unset_reaches_the_command(tmp_path, command, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nENV PYTHONPATH=/opt/connector\nCOPY src /opt/connector/src\n"
                f"WORKDIR /tmp\nCMD {command}\n"
            ),
            "src/__main__.py": "",
        },
    )
    assert image.covered is covered, image.reason


def test_stage_copy_wildcard_matches_a_leading_dot(tmp_path):
    # Copilot review of 00:37 UTC: Docker wildcards match a leading dot.
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine AS builder\nCOPY src /build\n"
                "FROM python:3.12-alpine\nCOPY --from=builder /build/* /opt/app/\n"
                'WORKDIR /opt/app\nCMD ["python3", "main.py"]\n'
            )
        },
    )
    assert image.covered, image.reason
    assert image.reason == "stamp at /opt/app/.connector_version.json"


def test_entry_script_handing_over_to_another_script(tmp_path):
    files = {
        "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
        "entrypoint.sh": "#!/bin/sh\nexec /opt/sample/run.sh\n",
        "src/run.sh": "#!/bin/sh\ncd /opt/sample && exec python3 main.py\n",
    }
    assert single(tmp_path, files).covered


@pytest.mark.parametrize(
    "script",
    [
        "#!/bin/sh\npython3 /usr/local/share/warmup.py\ncd /opt/sample\nexec python3 main.py\n",
        "#!/bin/sh\ncd /opt/sample\npython3 warmup.py\npython3 main.py\n",
    ],
)
def test_python_process_after_another_one_is_reported(tmp_path, script):
    # What the first python process does to the files is not modelled.
    files = {
        "Dockerfile": (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY src/warmup.py /usr/local/share/\n"
            'COPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n'
        ),
        "entrypoint.sh": script,
        "src/warmup.py": "",
    }
    image = single(tmp_path, files)
    assert image.reason == (
        "not supported: a python process starts after another one whose effects on the files are not modelled"
    )


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


@pytest.mark.parametrize(
    "run, command, reason",
    [
        # pycti resolves the script path: a link the model does not follow is reported.
        (
            "ln -s /opt/sample/main.py /main.py",
            '["python3", "/main.py"]',
            "not supported: python script /main.py is not a file of the image model",
        ),
        (
            "ln -sf /dev/null /opt/sample/.connector_version.json",
            '["python3", "/opt/sample/main.py"]',
            "no COPY carries a stamp into the final image",
        ),
        (
            "ln -s /usr/share/data /opt/sample",
            '["python3", "/opt/sample/main.py"]',
            "not supported: python script /opt/sample/main.py is not a file of the image model",
        ),
    ],
)
def test_symbolic_links(tmp_path, run, command, reason):
    image = single(
        tmp_path,
        {
            "Dockerfile": f"FROM python:3.12-alpine\nCOPY src /opt/sample\nRUN {run}\nCMD {command}\n"
        },
    )
    assert not image.covered
    assert image.reason == reason


def test_entry_point_found_on_an_extended_path(tmp_path):
    files = {
        "Dockerfile": (
            "FROM python:3.12-alpine\nENV PATH=/opt/tools/bin:$PATH\nCOPY src /opt/sample\n"
            'COPY start.sh /usr/local/bin/start-connector\nENTRYPOINT ["start-connector"]\n'
        ),
        "start.sh": "#!/bin/sh\ncd /opt/sample\nexec python3 main.py\n",
    }
    assert single(tmp_path, files).covered


def test_shell_form_entrypoint_ignores_cmd(tmp_path):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nENTRYPOINT python3 /opt/sample/main.py\nCMD ["python3", "/elsewhere/main.py"]\n'
        },
    )
    assert image.covered


@pytest.mark.parametrize(
    "dockerfile, reason",
    [
        # Copilot review of 01:21 UTC: any blank ends the instruction name.
        (
            "FROM python:3.12-alpine\nCOPY\tsrc /opt/src\n"
            "RUN\trm -f /opt/src/.connector_version.json\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "no COPY carries a stamp into the final image",
        ),
        # Copilot review of 01:21 UTC: ONBUILD triggers run in another stage.
        (
            "FROM python:3.12-alpine AS base\nONBUILD RUN rm -rf /opt/src\n"
            'FROM base\nCOPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: the ONBUILD instruction",
        ),
        # Copilot review of 01:21 UTC: the escape directive after another directive.
        (
            "# syntax=docker/dockerfile:1\n# escape=`\nFROM python:3.12-alpine\n"
            'COPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: the escape parser directive",
        ),
        (
            "# A comment ends the directives.\n# escape=`\nFROM python:3.12-alpine\n"
            'COPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "stamp at /opt/src/.connector_version.json",
        ),
        # The health check runs while the connector runs.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            "HEALTHCHECK --interval=5m CMD rm -f /opt/src/.connector_version.json\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "not supported: the HEALTHCHECK command changes files of the image",
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            "HEALTHCHECK --interval=5m CMD pgrep -f main.py > /dev/null || exit 1\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "stamp at /opt/src/.connector_version.json",
        ),
        # Copilot review of 01:56 UTC: the health check runs in the final image.
        (
            "FROM python:3.12-alpine\nHEALTHCHECK CMD rm -f /opt/src/.connector_version.json\n"
            'COPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: the HEALTHCHECK command changes files of the image",
        ),
        (
            "FROM python:3.12-alpine AS base\nHEALTHCHECK CMD rm -f /opt/src/.connector_version.json\n"
            'FROM base\nCOPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: the HEALTHCHECK command changes files of the image",
        ),
        (
            "FROM python:3.12-alpine AS base\nHEALTHCHECK CMD rm -f /opt/src/.connector_version.json\n"
            "FROM base\nHEALTHCHECK NONE\nCOPY src /opt/src\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "stamp at /opt/src/.connector_version.json",
        ),
        # Copilot review of 01:56 UTC: any blank ends a COPY flag.
        (
            "FROM python:3.12-alpine\nCOPY --exclude=**/*.json\t src /opt/src\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "no COPY carries a stamp into the final image",
        ),
        # Copilot review of 01:56 UTC: a stage copy may bring files the model
        # does not know.
        (
            "FROM python:3.12-alpine AS builder\nRUN touch /tmp/empty\n"
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            "COPY --from=builder /tmp/empty /opt/src/.connector_version.json\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "no COPY carries a stamp into the final image",
        ),
        # Copilot review of 01:21 UTC: copied directories get the --chmod mode too.
        (
            "FROM python:3.12-alpine\nCOPY --chmod=644 src /opt/src\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "no COPY carries a stamp into the final image",
        ),
        (
            "FROM python:3.12-alpine\nCOPY --chmod=755 src /opt/src\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "stamp at /opt/src/.connector_version.json",
        ),
    ],
)
def test_dockerfile_syntax(tmp_path, dockerfile, reason):
    image = single(tmp_path, {"Dockerfile": dockerfile})
    assert image.reason == reason


@pytest.mark.parametrize(
    "dockerfile, extra",
    [
        # Copilot review of 01:21 UTC: a file on PATH under the name of python runs.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY wrapper.sh /usr/local/bin/python3\nWORKDIR /opt/sample\n"
            "CMD python3 main.py\n",
            {
                "wrapper.sh": '#!/bin/sh\nrm -f /opt/sample/.connector_version.json\nexec /usr/local/bin/python3.12 "$@"\n'
            },
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY wrapper.sh /usr/local/bin/python3\nWORKDIR /opt/sample\n"
            'CMD ["python3", "main.py"]\n',
            {"wrapper.sh": '#!/bin/sh\ncd /tmp\nexec /usr/local/bin/python3.12 "$@"\n'},
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "RUN ln -sf /usr/bin/env /usr/local/bin/python3\nWORKDIR /opt/sample\n"
            'CMD ["python3", "main.py"]\n',
            {},
        ),
        # Copilot review of 01:56 UTC: also when the path is written in full.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY wrapper.sh /usr/local/bin/python3\n"
            "RUN /usr/local/bin/python3 -m compileall /opt/sample\n"
            'CMD ["python3.12", "/opt/sample/main.py"]\n',
            {"wrapper.sh": "#!/bin/sh\nrm -rf /opt/sample\n"},
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY wrapper.sh /usr/local/bin/python3\n"
            'CMD ["/usr/local/bin/python3", "/opt/sample/main.py"]\n',
            {
                "wrapper.sh": '#!/bin/sh\nrm -f /opt/sample/.connector_version.json\nexec /usr/local/bin/python3.12 "$@"\n'
            },
        ),
        # Copilot review of 02:24 UTC: env is a program found on PATH too.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY wrapper.sh /usr/local/bin/env\n"
            'CMD ["env", "python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": ENV_WRAPPER},
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY wrapper.sh /usr/local/bin/env\n"
            "CMD env python3 /opt/sample/main.py\n",
            {"wrapper.sh": ENV_WRAPPER},
        ),
        # Copilot review of 02:24 UTC: a chmod keeps the wrapper in place.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY wrapper.sh /usr/local/bin/python3\nRUN chmod 500 /usr/local/bin/python3\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": ENV_WRAPPER},
        ),
        # Copilot review of 02:24 UTC: the SHELL of RUN, a file the build wrote.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY --chmod=755 wrapper.sh /opt/sh\n"
            'SHELL ["/opt/sh", "-c"]\nRUN echo ready\nCMD ["python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": ENV_WRAPPER},
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY clean.sh /usr/local/bin/rm\n"
            'RUN rm -f /tmp/cache\nCMD ["python3", "/opt/sample/main.py"]\n',
            {"clean.sh": "#!/bin/sh\n/bin/rm -rf /opt/sample\n"},
        ),
    ],
)
def test_programs_shadowed_on_the_path(tmp_path, dockerfile, extra):
    image = single(tmp_path, {"Dockerfile": dockerfile, **extra})
    assert not image.covered, image.reason


def test_module_shadowed_by_a_file_of_the_build(tmp_path):
    # Copilot review of 02:24 UTC: python -m compileall imports the working
    # directory first.
    files = {
        "Dockerfile": (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\n"
            'RUN python3 -m compileall .\nCMD ["python3", "/opt/sample/main.py"]\n'
        ),
        "src/compileall.py": "import os\nos.remove('.connector_version.json')\n",
    }
    image = single(tmp_path, files)
    assert image.reason == (
        "not supported: python -m compileall may run /opt/sample/compileall.py,"
        " a file the build wrote, instead of the module of the interpreter"
    )


@pytest.mark.parametrize(
    "command, covered",
    [
        # Copilot review of 02:24 UTC: a plain assignment is not exported.
        ('["sh", "-c", "PYTHONPATH=/opt/connector; exec python3 -m src"]', False),
        (
            '["sh", "-c", "export PYTHONPATH=/opt/connector; exec python3 -m src"]',
            True,
        ),
        (
            '["sh", "-c", "PYTHONPATH=/opt/connector; export PYTHONPATH; exec python3 -m src"]',
            True,
        ),
        (
            '["sh", "-c", "set -a; PYTHONPATH=/opt/connector; exec python3 -m src"]',
            True,
        ),
        ('["sh", "-c", "PYTHONPATH=/opt/connector exec python3 -m src"]', True),
    ],
)
def test_only_exported_variables_reach_python(tmp_path, command, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nCOPY src /opt/connector/src\n"
                f"WORKDIR /tmp\nCMD {command}\n"
            ),
            "src/__main__.py": "",
        },
    )
    assert image.covered is covered, image.reason


def test_module_file_wins_over_a_namespace_directory(tmp_path):
    # Copilot review of 02:24 UTC: pkg.py is imported before pkg/ without
    # __init__.py, so its directory is the one pycti reads.
    files = {
        "Dockerfile": (
            "FROM python:3.12-alpine\nENV PYTHONPATH=/opt\nCOPY src /opt/pkg\n"
            'COPY pkg.py /opt/pkg.py\nWORKDIR /tmp\nCMD ["python3", "-m", "pkg"]\n'
        ),
        "src/__main__.py": "",
        "pkg.py": "",
    }
    assert not single(tmp_path, files).covered
    del files["pkg.py"]
    files["Dockerfile"] = files["Dockerfile"].replace("COPY pkg.py /opt/pkg.py\n", "")
    image = single(tmp_path / "namespace", files)
    assert image.reason == "stamp at /opt/pkg/.connector_version.json"


def test_symbolic_links_of_the_context(tmp_path):
    # Copilot review of 02:24 UTC: COPY keeps a link, which pycti resolves.
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/app\nWORKDIR /tmp\nCMD ["python3", "/opt/app/main.py"]\n',
            "src/nested/a/b/c/d/e/main.py": "",
        },
    )
    (connector / "src/main.py").unlink()
    try:
        (connector / "src/main.py").symlink_to("nested/a/b/c/d/e/main.py")
    except OSError:
        pytest.skip("symbolic links cannot be created here")
    [image] = result(tmp_path, connector)
    assert image.reason == (
        "not supported: python script /opt/app/main.py is not a file of the image model"
    )


@pytest.mark.parametrize(
    "env, command, covered",
    [
        # Copilot review of 01:21 UTC: -P keeps PYTHONPATH, -I ignores it.
        ("PYTHONPATH=/opt/connector", '["python3", "-P", "-m", "src"]', True),
        ("PYTHONPATH=/opt/connector", '["python3", "-I", "-m", "src"]', False),
        (
            "PYTHONSAFEPATH=1",
            '["sh", "-c", "cd /opt/connector && python3 -m src"]',
            False,
        ),
        (
            "PYTHONSAFEPATH=",
            '["sh", "-c", "cd /opt/connector && python3 -m src"]',
            True,
        ),
        # Copilot review of 01:21 UTC: a relative cd is searched in CDPATH.
        (
            "CDPATH=/elsewhere",
            '["sh", "-c", "cd opt/connector && python3 -m src"]',
            False,
        ),
        (
            "CDPATH=/elsewhere",
            '["sh", "-c", "cd /opt/connector && python3 -m src"]',
            True,
        ),
        # Copilot review of 01:56 UTC: CDPATH assigned for the cd command only.
        (
            "UNUSED=1",
            '["sh", "-c", "CDPATH=/elsewhere cd opt/connector && python3 -m src"]',
            False,
        ),
        ("UNUSED=1", '["sh", "-c", "cd opt/connector && python3 -m src"]', True),
    ],
)
def test_python_search_path_and_cdpath(tmp_path, env, command, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                f"FROM python:3.12-alpine\nENV {env}\nCOPY src /opt/connector/src\n"
                f"WORKDIR /\nCMD {command}\n"
            ),
            "src/__main__.py": "",
        },
    )
    assert image.covered is covered, image.reason


def test_command_substitution_in_an_entry_script(tmp_path):
    # Copilot review of 01:21 UTC: the substitution runs in the entry script too.
    files = {
        "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
        "entrypoint.sh": '#!/bin/sh\nUNUSED="$(rm -f /opt/sample/.connector_version.json)"\ncd /opt/sample\nexec python3 main.py\n',
    }
    assert not single(tmp_path, files).covered


def test_workflow_watches_every_file_the_check_reads():
    # Copilot reviews of 21:40 and 23:37 UTC: any file of a connector (an entry
    # script has no fixed name) or of the shared build must run the check.
    text = WORKFLOW.read_text(encoding="utf-8")
    sections = re.split(r"^  (push|pull_request|merge_group):", text, flags=re.M)
    filters = {sections[i]: sections[i + 1] for i in range(1, len(sections) - 1, 2)}
    for event in ("push", "pull_request"):
        paths = set(re.findall(r"^\s+- '([^']+)'", filters[event], flags=re.M))
        for directory in check.WATCHED_DIRECTORIES:
            assert f"{directory}/**" in paths, f"{event} does not watch {directory}"
        for name in (
            check.UBI9_DOCKERFILE,
            # Copilot review of 00:11 UTC: the ignore file the shared Dockerfile reads.
            f"{check.UBI9_DOCKERFILE}.dockerignore",
            check.UBI9_CONNECTORS,
            ".github/actions/build-connector-image/**",
            ".github/scripts/check_connector_stamp.py",
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
