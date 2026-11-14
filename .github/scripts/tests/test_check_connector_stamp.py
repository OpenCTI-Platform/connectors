import gzip
import importlib.util
import io
import json
import re
import tarfile
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


def tar_archive(*names):
    """A tar archive holding an empty file under each name."""
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for name in names:
            archive.addfile(tarfile.TarInfo(name), io.BytesIO(b""))
    return payload.getvalue()


def make_connector(root, files, path="external-import/sample", src=True):
    """A connector with ``files``, and a ``src/main.py`` unless ``src`` is false."""
    connector = root / path
    connector.mkdir(parents=True, exist_ok=True)
    for name, content in {**({"src/main.py": ""} if src else {}), **files}.items():
        target = connector / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return connector


def result(root, connector, ubi9=()):
    return check.check_connector(connector, root, set(ubi9))


def single(root, files, src=True):
    [image] = result(root, make_connector(root, files, src=src))
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
        # Copilot review of 07:32 UTC: a cd that may fail leaves the shell where
        # it was.
        (
            "#!/bin/sh\ncd /opt/sample/missing\nexec python3 ../main.py\n",
            "a 'cd' to a directory the image model does not know",
        ),
        (
            "#!/bin/sh\ncd /opt/sample/missing && exec python3 ../main.py\n",
            "a directory change in an && list",
        ),
        # An exec after && may not run: the script then goes on.
        (
            "#!/bin/sh\nfalse && exec python3 main.py\n"
            "rm -f .connector_version.json\nexec python3 main.py\n",
            "a python process starts after another one",
        ),
        # A pipeline part or a background job runs next to the commands that
        # follow it, which may change its files while it starts.
        (
            "#!/bin/sh\npython3 main.py &\nrm -f .connector_version.json\nwait\n",
            "the connector started in a pipeline or a background job",
        ),
        (
            "#!/bin/sh\npython3 main.py | rm -f .connector_version.json\n",
            "the connector started in a pipeline or a background job",
        ),
        (
            "#!/bin/sh\nsh -c 'exec python3 main.py' &\nwait\n",
            "the connector started in a pipeline or a background job",
        ),
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


@pytest.mark.parametrize(
    "script, covered",
    [
        # Copilot review of 07:32 UTC: a line ending with an escaped backslash,
        # or with a backslash in a comment, does not go on with the next one.
        (
            "#!/bin/sh\necho ready \\\\\nrm -f /opt/sample/.connector_version.json\nexec python3 main.py\n",
            False,
        ),
        (
            "#!/bin/sh\n# clean up \\\nrm -f /opt/sample/.connector_version.json\nexec python3 main.py\n",
            False,
        ),
        (
            "#!/bin/sh\necho ready \\\nrm -f /opt/sample/.connector_version.json\nexec python3 main.py\n",
            True,
        ),
        (
            '#!/bin/sh\necho "ready \\\nrm -f /opt/sample/.connector_version.json"\nexec python3 main.py\n',
            True,
        ),
    ],
)
def test_entry_script_line_continuations(tmp_path, script, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nWORKDIR /opt/sample\nENTRYPOINT ["/entrypoint.sh"]\n',
            "entrypoint.sh": script,
        },
    )
    assert image.covered is covered, image.reason


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
        # Copilot review of 05:48 UTC: a test after an action does not narrow it.
        ("find /opt/src -name '*.json' -delete -name '*.pyc'", False),
        ("find /opt/src -name '*.json' -exec rm {} \\; -name '*.pyc'", False),
        ("find /opt/src -name '*.pyc' -delete -name '*.json'", True),
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
        # Copilot review of 07:32 UTC: Go negates a class with "^" only.
        ("src/.connector_version.jso[!x]\n", True),
        ("src/.connector_version.jso[^x]\n", False),
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
        # Copilot review of 07:32 UTC: ADD copies a file that is not an archive
        # as it is, whatever its name.
        ("COPY src /opt/sample\nADD notes.tar.gz /opt/sample/", True),
        # Copilot review of 07:32 UTC: explicit clauses that keep files readable
        # and directories searchable.
        ("COPY --chmod=u=rwx,go=rx src /opt/sample", True),
        ("COPY --chmod=a=rX src /opt/sample", True),
        ("COPY --chmod=u=rw,go=r src /opt/sample", False),
        ("COPY --chmod=u=rwx,go= src /opt/sample", False),
        ("COPY --chmod=a+rX,o-r src /opt/sample", False),
        ("COPY --chmod=g=u src /opt/sample", False),
    ],
)
def test_permissions_and_volumes(tmp_path, instructions, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": f'FROM python:3.12-alpine\n{instructions}\nWORKDIR /opt/sample\nCMD ["python3", "main.py"]\n',
            "payload.tar": tar_archive("main.py"),
            "notes.tar.gz": "release notes, not an archive",
        },
    )
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "source, covered",
    [
        # Copilot review of 07:32 UTC: COPY sources follow Go's filepath.Match,
        # where "[!x]" matches "!" or "x" and only "^" negates a class.
        ("src/.connector_version.jso[!x]", False),
        ("src/.connector_version.jso[^x]", True),
    ],
)
def test_copy_source_bracket_classes(tmp_path, source, covered):
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                f"FROM python:3.12-alpine\nCOPY src/main.py /opt/sample/\nCOPY {source} /opt/sample/\n"
                'WORKDIR /opt/sample\nCMD ["python3", "main.py"]\n'
            ),
            "src/.connector_version.jsox": "",
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


WHOLE_CONTEXT_DOCKERFILE = (
    "FROM python:3.12-alpine\nCOPY . /opt\n{copy}WORKDIR /opt/src\n"
    'CMD ["python3", "main.py"]\n'
)
OTHER_STAMP = '{"version": "6.1.0", "slug": "other-connector"}'


@pytest.mark.parametrize(
    "copy, files, reason",
    [
        # Copilot review of 12:15 UTC: pycti keeps the first identity file it
        # reads, a nearer one the build stamp does not stand for included.
        (
            "COPY wrong.json /opt/src/.connector_version.json\n",
            {"wrong.json": OTHER_STAMP},
            "pycti reads /opt/src/.connector_version.json (wrong.json of the build"
            " context, version '6.1.0') before any build stamp",
        ),
        (
            "COPY --from=python:3.12-alpine /etc/os-release /opt/src/.connector_version.json\n",
            {},
            "pycti reads /opt/src/.connector_version.json before any build stamp,"
            " and a build step put content the model does not know there",
        ),
        # A file pycti skips (not JSON, no usable version) does not stop it.
        (
            "COPY wrong.json /opt/src/.connector_version.json\n",
            {"wrong.json": "not json"},
            "stamp at /opt/.connector_version.json",
        ),
        (
            "COPY wrong.json /opt/src/.connector_version.json\n",
            {"wrong.json": '{"version": "unknown", "slug": "other-connector"}'},
            "stamp at /opt/.connector_version.json",
        ),
        ("", {}, "stamp at /opt/src/.connector_version.json"),
        # In each directory pycti reads the manifest of a source checkout first.
        (
            "COPY __metadata__ /opt/src/__metadata__\n",
            {
                "__metadata__/connector_manifest.json": '{"container_version": "rolling"}'
            },
            "pycti reads /opt/src/__metadata__/connector_manifest.json"
            " (__metadata__/connector_manifest.json of the build context, version"
            " 'rolling') before any build stamp",
        ),
    ],
)
def test_pycti_keeps_the_first_identity_file(tmp_path, copy, files, reason):
    dockerfile = WHOLE_CONTEXT_DOCKERFILE.format(copy=copy)
    image = single(tmp_path, {"Dockerfile": dockerfile, **files})
    assert image.reason == reason


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
    """A flat-layout packaged connector: its package at the top, no src/
    directory (which would make setuptools' automatic discovery use src/)."""
    files = {"Dockerfile": dockerfile, "sample_connector/__main__.py": "", **packaging}
    if init:
        files["sample_connector/__init__.py"] = ""
    if ignore is not None:
        files[".dockerignore"] = ignore
    return single(root, files, src=False)


@pytest.mark.parametrize(
    "find, reason",
    [
        # Copilot review of 08:47 UTC: automatic discovery takes the packages of
        # src/ when it exists, and none of the top level.
        ("", "not supported: module sample_connector is not a file of the image model"),
        # A find option is not automatic discovery: its roots are read as given.
        ('[tool.setuptools.packages.find]\nwhere = ["."]\n', None),
    ],
)
def test_automatic_discovery_takes_the_src_layout(tmp_path, find, reason):
    data = '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
    image = packaged(tmp_path, {"pyproject.toml": find + data, "src/helper.py": ""})
    if reason:
        assert not image.covered
        assert image.reason == reason
    else:
        assert image.covered, image.reason


@pytest.mark.parametrize(
    "copies, reason",
    [
        # Copilot review of 12:40 UTC: a package of the working directory whose
        # initializer a build step wrote is imported before the installed one.
        (
            "COPY --from=python:3.12-alpine /etc/os-release /opt/app/sample_connector/__init__.py\n",
            "not supported: python -m sample_connector: /opt/app/sample_connector holds"
            " what a build command wrote",
        ),
        # Without an initializer it is a namespace portion: the installed
        # package wins.
        ("", "stamp at /<site-packages>/sample_connector/.connector_version.json"),
    ],
)
def test_module_with_an_unknown_initializer(tmp_path, copies, reason):
    data = '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
    dockerfile = PACKAGED_DOCKERFILE.replace(
        "CMD",
        "COPY sample_connector/__main__.py /opt/app/sample_connector/__main__.py\n"
        f"{copies}WORKDIR /opt/app\nCMD",
    )
    image = packaged(tmp_path, {"pyproject.toml": data}, dockerfile)
    assert image.reason == reason


@pytest.mark.parametrize(
    "build, reason",
    [
        # Copilot review of 09:21 UTC: an empty src/ directory the build made
        # selects the src layout as well.
        (
            "RUN mkdir /opt/build/src && pip install /opt/build && rm -rf /opt/build",
            "not supported: module sample_connector is not a file of the image model",
        ),
        (
            "RUN mkdir -p /opt/build/src/inner && pip install /opt/build",
            "not supported: module sample_connector is not a file of the image model",
        ),
        # What a build command wrote there is not known: its layout neither.
        (
            "RUN ln -s /tmp /opt/build/src && pip install /opt/build",
            "not supported: automatic discovery in /opt/build, whose src holds what a build command wrote",
        ),
        (
            "RUN mkdir /opt/build/other && pip install /opt/build && rm -rf /opt/build",
            None,
        ),
    ],
)
def test_automatic_discovery_reads_the_build_directories(tmp_path, build, reason):
    data = '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
    dockerfile = PACKAGED_DOCKERFILE.replace(
        "RUN pip install /opt/build && rm -rf /opt/build", build
    )
    image = packaged(tmp_path, {"pyproject.toml": data}, dockerfile)
    if reason:
        assert not image.covered
        assert image.reason == reason
    else:
        assert image.covered, image.reason


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


def test_installed_package_reads_no_stamp_above_site_packages(tmp_path):
    # Copilot review of 04:10 UTC: the installed package lies four levels below
    # /usr/local, so pycti does not reach a stamp in "/" from it.
    dockerfile = PACKAGED_DOCKERFILE.replace(
        "CMD", "COPY .connector_version.json /\nWORKDIR /opt/a/b/c/d/e\nCMD"
    )
    image = packaged(
        tmp_path, {"pyproject.toml": "[project]\nname = 'sample'\n"}, dockerfile
    )
    assert not image.covered, image.reason


def test_a_stamp_above_the_physical_site_packages_is_reported(tmp_path):
    # Copilot review of 09:00 UTC: pycti reaches /usr/local from a package in
    # /usr/local/lib/python3.12/site-packages, but whether the interpreter
    # installs there is not known to the image model.
    dockerfile = PACKAGED_DOCKERFILE.replace(
        "CMD", "COPY .connector_version.json /usr/local/\nWORKDIR /tmp\nCMD"
    )
    image = packaged(
        tmp_path, {"pyproject.toml": "[project]\nname = 'sample'\n"}, dockerfile
    )
    assert not image.covered
    assert image.reason.startswith(
        "stamp at /usr/local/.connector_version.json: pycti reads it only from"
    ), image.reason


def test_module_also_in_the_user_site_packages(tmp_path):
    # The user site-packages comes before the installed packages.
    dockerfile = PACKAGED_DOCKERFILE.replace(
        "CMD",
        "COPY sample_connector /root/.local/lib/python3.12/site-packages/sample_connector\nCMD",
    )
    pyproject = {
        "pyproject.toml": '[tool.setuptools.package-data]\nsample_connector = [".connector_version.json"]\n'
    }
    image = packaged(tmp_path, pyproject, dockerfile)
    assert image.reason == (
        "not supported: python -m sample_connector: a module sample_connector also"
        " lies in /root/.local/lib/python3.12/site-packages/sample_connector"
    )


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
        {
            "pyproject.toml": (
                '[build-system]\nbuild-backend = "setuptools.build_meta"\n'
                '[tool.setuptools.package-data]\n"*" = [".connector_version.json"]\n'
            )
        },
    ],
)
def test_package_data_that_selects_the_stamp(tmp_path, packaging):
    assert packaged(tmp_path, packaging).covered


def test_local_project_of_another_build_backend_is_reported(tmp_path):
    # Copilot review of 05:48 UTC: pip runs the backend, and its build hooks,
    # for every local install, even when the stamp lies outside any package.
    image = single(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nCOPY src /opt/src\nRUN pip install /opt/src\n"
                'CMD ["python3", "/opt/src/main.py"]\n'
            ),
            "src/pyproject.toml": '[build-system]\nbuild-backend = "hatchling.build"\n',
        },
    )
    assert image.reason == "not supported: /opt/src: the build backend hatchling.build"


@pytest.mark.parametrize(
    "packaging, reason",
    [
        (
            {
                "pyproject.toml": '[build-system]\nbuild-backend = "hatchling.build"\n',
                "setup.cfg": "[options.package_data]\nsample_connector = .connector_version.json\n",
            },
            "/opt/build: the build backend hatchling.build",
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
            "RUN pip install --no-cache-dir --log /tmp/pip.log requests",
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
        # Copilot review of 05:25 UTC: what goes through a link the build
        # created acts on the files it stands for.
        (
            "RUN ln -s /opt/src /tmp/app; cd /tmp/app; rm -f .connector_version.json",
            False,
        ),
        (
            "RUN ln /opt/src/.connector_version.json /tmp/h && echo x > /tmp/h",
            False,
        ),
        (
            "RUN ln -s /usr/bin/python3 /usr/local/bin/py && rm -f /usr/local/bin/py",
            True,
        ),
        # Copilot review of 05:25 UTC: -execdir resolves operands from each match.
        (
            "RUN touch /opt/src/marker.txt && find /opt/src -name marker.txt -execdir rm -f .connector_version.json \\;",
            False,
        ),
        # Copilot review of 05:25 UTC: a quoted or escaped wildcard is literal,
        # also in the exec form and in a quoted expansion; sh -c reads its
        # script again.
        ("RUN rm -f '/opt/src/.connector_version.*'", True),
        ("RUN rm -f /opt/src/.connector_version.\\*", True),
        ('RUN ["rm", "-f", "/opt/src/.connector_version.*"]', True),
        ('ENV P=/opt/src/.connector_version.*\nRUN rm -f "$P"', True),
        ("ENV P=/opt/src/.connector_version.*\nRUN rm -f $P", False),
        ("RUN sh -c 'rm -f /opt/src/.connector_version.*'", False),
        # Copilot review of 04:29 UTC: pip commands, variables and configuration
        # files form a closed set too.
        ("RUN pip wheel /opt/src", False),
        ("RUN pip download -d /tmp requests", False),
        ("RUN pip config set global.target /opt/src", False),
        ("RUN pip freeze > /tmp/requirements.txt && pip check", True),
        ("ENV PIP_TARGET=/opt/elsewhere\nRUN pip install requests", False),
        ("ENV PIP_NO_CACHE_DIR=1\nRUN pip install requests", True),
        # Copilot review of 04:56 UTC: the environment of the command counts.
        ("RUN PIP_REPORT=/opt/src/.connector_version.json pip install requests", False),
        (
            "RUN env PIP_LOG=/opt/src/.connector_version.json python3 -m pip install requests",
            False,
        ),
        ("RUN echo '[global]' > /etc/pip.conf && pip install requests", False),
        # Copilot review of 04:10 UTC: env options, a command after && that may
        # not run, pip global options.
        ("RUN env -S 'rm -f /opt/src/.connector_version.json' true", False),
        (
            'ENV APP=/opt/src\nRUN false && APP=/tmp; rm -f "$APP/.connector_version.json"',
            False,
        ),
        (
            "WORKDIR /opt/src\nRUN false && cd /tmp; rm -f .connector_version.json",
            False,
        ),
        ("WORKDIR /opt/src\nRUN cd /tmp && rm -f .connector_version.json", True),
        # Copilot review of 07:32 UTC: a cd that may fail leaves the shell where
        # it was.
        ("WORKDIR /opt/src\nRUN cd /opt/missing; rm -f .connector_version.json", False),
        (
            "WORKDIR /opt/src\nRUN cd /opt/missing && rm -f .connector_version.json; true",
            True,
        ),
        ("RUN pip --log /opt/src/.connector_version.json install requests", False),
        (
            "RUN python3 -m pip --log /opt/src/.connector_version.json install requests",
            False,
        ),
        ("RUN pip --no-cache-dir --log /tmp/pip.log install requests", True),
        # Copilot review of 03:54 UTC: <> may write its target; a wildcard
        # chmod that matches a directory needs its search permission.
        ("RUN printf '{}' 1<> /opt/src/.connector_version.json", False),
        ("RUN chmod 644 /opt/*", False),
        ("RUN chmod 755 /opt/*", True),
        # Copilot review of 03:33 UTC: an arithmetic expansion that assigns; an
        # ENV value wins over a later ARG.
        (
            "ENV N=0\nRUN echo $((N=1)); rm -f /opt/src$N/.connector_version.json",
            False,
        ),
        (
            'ENV APP=/opt/src\nARG APP=/tmp\nRUN rm -f "$APP/.connector_version.json"',
            False,
        ),
        ("RUN echo $((1 + 2 == 3))", True),
        # Copilot review of 03:01 UTC: a substitution inside a parameter
        # expansion; the roots of find after its leading options.
        (
            'RUN echo "${UNSET:-$(rm -f /opt/src/.connector_version.json)}"',
            False,
        ),
        ("WORKDIR /tmp\nRUN find -P /opt/src -name '*.json' -delete", False),
        ("WORKDIR /tmp\nRUN find -L /opt/src -name '*.json' -delete", False),
        ("WORKDIR /tmp\nRUN find -P /opt/src -name '*.pyc' -print", True),
        # Copilot review of 02:45 UTC: python -mNAME is python -m NAME; sudo
        # changes the environment and may change the directory.
        ("RUN python3 -mvenv --clear --without-pip /opt/src", False),
        (
            "RUN python3 -mpip install --report /opt/src/.connector_version.json requests",
            False,
        ),
        ("RUN sudo rm -f /tmp/cache", False),
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
        # Copilot review of 09:21 UTC: the command substitutions of a target
        # that is read or duplicated run before the command too.
        (
            'RUN true < "$(rm -f /opt/src/.connector_version.json; printf /dev/null)"',
            False,
        ),
        ("RUN true 0<&$(rm -f /opt/src/.connector_version.json; echo 0)", False),
        ("RUN < $(rm -f /opt/src/.connector_version.json; echo /dev/null)", False),
        ("RUN cat < /opt/src/main.py > /tmp/main.py 2>&1", True),
        # Copilot review of 09:21 UTC: playwright is reviewed for installing
        # browsers; its other subcommands write where they are told.
        ("RUN playwright install chromium --with-deps --only-shell", True),
        ("RUN playwright pdf about:blank /opt/src/.connector_version.json", False),
        ("RUN playwright screenshot about:blank /tmp/page.png", False),
        ("RUN playwright", False),
        # Copilot review of 11:49 UTC: what find -exec mv puts at its
        # destination is not followed.
        (
            "RUN find /tmp -maxdepth 0 -exec mv /tmp/wrapper /usr/local/bin/python3 \\;",
            False,
        ),
        ("RUN find /opt/src -name '*.pyc' -exec mv {} /tmp \\;", False),
        ("RUN find /opt/src -name '*.pyc' -exec rm -f {} +", True),
        # Copilot review of 12:40 UTC: a recursive rm, or a mv, takes its
        # directories away, so a later cd into one fails and stays where it was.
        (
            "WORKDIR /opt/src\nRUN mkdir /tmp/gone; rm -rf /tmp/gone; cd /tmp/gone;"
            " rm -f .connector_version.json",
            False,
        ),
        (
            "WORKDIR /opt/src\nRUN mkdir /tmp/gone; mv /tmp/gone /tmp/moved; cd /tmp/gone;"
            " rm -f .connector_version.json",
            False,
        ),
        (
            "WORKDIR /opt/src\nRUN mkdir /tmp/gone; rm -f /tmp/gone; cd /tmp/gone;"
            " rm -f .connector_version.json",
            True,
        ),
        # Copilot review of 12:58 UTC: find -delete takes the directories it
        # matches away as well.
        (
            "WORKDIR /opt/src\nRUN mkdir /tmp/gone; find /tmp/gone -delete; cd /tmp/gone;"
            " rm -f .connector_version.json",
            False,
        ),
        (
            "WORKDIR /opt/src\nRUN mkdir /tmp/gone; find /tmp -name gone -delete; cd /tmp/gone;"
            " rm -f .connector_version.json",
            False,
        ),
        (
            "WORKDIR /opt/src\nRUN mkdir /tmp/gone; find /tmp/gone -type f -delete; cd /tmp/gone;"
            " rm -f .connector_version.json",
            True,
        ),
        # Copilot review of 12:58 UTC: ${NAME:=word} and ${NAME=word} set the
        # variable, nested in another expansion too; quoted or escaped, they are
        # literal text.
        ("RUN bash -c ': \"${GLOBIGNORE:=x}\"; rm -rf /opt/src/*'", False),
        ("RUN bash -c ': \"${GLOBIGNORE=x}\"; rm -rf /opt/src/*'", False),
        ("RUN bash -c ': \"${UNSET:-${GLOBIGNORE:=x}}\"; rm -rf /opt/src/*'", False),
        ("RUN bash -c ': \"${GLOBIGNORE:-x}\"; rm -rf /opt/src/*'", True),
        ("RUN echo '${GLOBIGNORE:=x}'; rm -rf /opt/src/*", True),
        ("RUN echo \\${GLOBIGNORE:=x}; rm -rf /opt/src/*", True),
        ('RUN echo "\\${GLOBIGNORE:=x}"; rm -rf /opt/src/*', True),
        # Copilot review of 12:40 UTC: the initializer of a package that python
        # -m imports first may hold what a build step wrote.
        (
            "COPY --from=python:3.12-alpine /etc/os-release /opt/src/pip/__init__.py\n"
            "WORKDIR /opt/src\nRUN python3 -m pip install requests",
            False,
        ),
        (
            "COPY --from=python:3.12-alpine /etc/os-release /opt/src/tools/__init__.py\n"
            "WORKDIR /opt/src\nRUN python3 -m pip install requests",
            True,
        ),
        # Copilot review of 13:37 UTC: no shell reads the exec form, so a
        # separator there is an argument.
        (
            'RUN ["printf", "%s\\n", ";", "rm", "-f", "/opt/src/.connector_version.json"]',
            True,
        ),
        (
            'RUN ["printf", "%s\\n", "&&", "rm", "-f", "/opt/src/.connector_version.json"]',
            True,
        ),
        ('RUN ["rm", "-f", "/opt/src/.connector_version.json"]', False),
        # A device holds no file, unless the build made it a link to one.
        ("RUN ls /opt/src > /dev/null 2> /dev/stderr", True),
        (
            "RUN ln -sf /opt/src/.connector_version.json /dev/stdout && echo x > /dev/stdout",
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
    # Copilot review of 03:54 UTC: find reaches them by their native path too.
    found = PACKAGED_DOCKERFILE.replace(
        "&& rm -rf /opt/build",
        "&& rm -rf /opt/build && find /usr/local/lib/python3.12/site-packages/sample_connector -name '*.json' -delete",
    )
    assert not packaged(tmp_path / "find", pyproject, dockerfile=found).covered
    above = PACKAGED_DOCKERFILE.replace(
        "&& rm -rf /opt/build",
        "&& rm -rf /opt/build && find /usr/local/lib -name '.connector_*' -delete",
    )
    assert not packaged(tmp_path / "above", pyproject, dockerfile=above).covered
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
        # Copilot review of 03:54 UTC: exec in a nested shell ends that shell only.
        "#!/bin/sh\ncd /opt/sample\nsh -c 'exec python3 warmup.py'\nexec python3 main.py\n",
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
            "pycti reads /opt/sample/.connector_version.json before any build stamp,"
            " and a build step put content the model does not know there",
        ),
        (
            # Into an existing directory, ln creates /opt/sample/data instead.
            "rm -rf /opt/sample && ln -s /usr/share/data /opt/sample",
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
        # Copilot review of 05:25 UTC: ENTRYPOINT clears an inherited CMD only.
        (
            'FROM python:3.12-alpine\nCOPY src /opt/src\nWORKDIR /opt/src\nCMD ["main.py"]\n'
            'ENTRYPOINT ["python3"]\n',
            "stamp at /opt/src/.connector_version.json",
        ),
        (
            'FROM python:3.12-alpine AS base\nCMD ["main.py"]\nFROM base\nCOPY src /opt/src\n'
            'WORKDIR /opt/src\nENTRYPOINT ["python3"]\n',
            "not supported: python started without a script or a module",
        ),
        # bash runs the file of BASH_ENV before each script.
        (
            'FROM python:3.12-alpine\nENV BASH_ENV=/opt/env.sh\nSHELL ["/bin/bash", "-c"]\n'
            'COPY src /opt/src\nRUN true\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: bash with BASH_ENV set",
        ),
        # Copilot review of 09:00 UTC: bash turns on the options BASHOPTS and
        # SHELLOPTS list (dotglob makes * match the stamp).
        (
            'FROM python:3.12-alpine\nENV BASHOPTS=dotglob\nSHELL ["/bin/bash", "-c"]\n'
            "COPY src /opt/src\nRUN rm -rf /opt/src/*\nCOPY src/main.py /opt/src/\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "not supported: bash with BASHOPTS set",
        ),
        (
            'FROM python:3.12-alpine\nENV SHELLOPTS=noglob\nSHELL ["/bin/bash", "-c"]\n'
            'COPY src /opt/src\nRUN true\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: bash with SHELLOPTS set",
        ),
        # Copilot review of 04:10 UTC: shell options that change what a command
        # does (bash dotglob makes * match the stamp).
        (
            'FROM python:3.12-alpine\nSHELL ["/bin/bash", "-O", "dotglob", "-c"]\n'
            'COPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: shell option -O",
        ),
        (
            'FROM python:3.12-alpine\nSHELL ["/bin/bash", "-eux", "-o", "pipefail", "-c"]\n'
            'COPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "stamp at /opt/src/.connector_version.json",
        ),
        # Copilot review of 03:54 UTC: another frontend may read the
        # instructions differently.
        (
            "# syntax=example.com/frontend:1\nFROM python:3.12-alpine\n"
            'COPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: the Dockerfile frontend example.com/frontend:1",
        ),
        (
            "# syntax=docker.io/docker/dockerfile:1.27-labs\nFROM python:3.12-alpine\n"
            'COPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n',
            "stamp at /opt/src/.connector_version.json",
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
        # Copilot review of 05:48 UTC: the shell form of HEALTHCHECK runs with the
        # SHELL of the image, as RUN does.
        (
            'FROM python:3.12-alpine\nENV BASH_ENV=/opt/env.sh\nSHELL ["/bin/bash", "-c"]\n'
            'COPY src /opt/src\nHEALTHCHECK CMD true\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: bash with BASH_ENV set",
        ),
        (
            'FROM python:3.12-alpine\nENV BASH_ENV=/opt/env.sh\nSHELL ["/bin/bash", "-c"]\n'
            'COPY src /opt/src\nHEALTHCHECK CMD ["true"]\nCMD ["python3", "/opt/src/main.py"]\n',
            "stamp at /opt/src/.connector_version.json",
        ),
        (
            'FROM python:3.12-alpine\nSHELL ["/usr/bin/pwsh", "-c"]\nCOPY src /opt/src\n'
            'HEALTHCHECK CMD true\nCMD ["python3", "/opt/src/main.py"]\n',
            "not supported: HEALTHCHECK through the shell /usr/bin/pwsh",
        ),
        # Copilot review of 11:49 UTC: a link the health check makes changes the
        # image as much as a file it writes.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            "HEALTHCHECK CMD ln -sf /tmp/wrapper /usr/local/bin/python3\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            "not supported: the HEALTHCHECK command changes files of the image",
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            'HEALTHCHECK CMD ["ln", "-sf", "/tmp/wrapper", "/usr/local/bin/python3"]\n'
            'CMD ["python3", "/opt/src/main.py"]\n',
            "not supported: the HEALTHCHECK command changes files of the image",
        ),
        # Copilot review of 13:37 UTC: no shell reads the exec form, so a
        # separator there is an argument.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            'HEALTHCHECK CMD ["printf", "%s", ";", "ln", "-sf", "/tmp/wrapper", "/usr/local/bin/python3"]\n'
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
            "pycti reads /opt/src/.connector_version.json before any build stamp,"
            " and a build step put content the model does not know there",
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


def test_healthcheck_probe_leaves_the_stage_alone(tmp_path):
    # Copilot review of 11:49 UTC: the health check runs on its own copy of the
    # stage, which the start command is read from afterwards.
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            'CMD ["python3", "/opt/src/main.py"]\n'
        },
    )
    model = check.ImageModel(connector, connector / "Dockerfile", {})
    stage = model.final
    state = (
        dict(stage.files),
        set(stage.dirs),
        set(stage.replaced),
        dict(stage.links),
        set(stage.unknown_dirs),
    )
    stage.healthcheck = (["ln", "-sf", "/tmp/wrapper", "/usr/local/bin/python3"], False)
    with pytest.raises(check.Unsupported, match="changes files of the image"):
        model._check_healthcheck(stage)
    stage.healthcheck = ("mkdir -p /opt/health", True)
    with pytest.raises(check.Unsupported, match="changes files of the image"):
        model._check_healthcheck(stage)
    assert (
        stage.files,
        stage.dirs,
        stage.replaced,
        stage.links,
        stage.unknown_dirs,
    ) == state


@pytest.mark.parametrize(
    "base, covered",
    [
        ("python:3.12-alpine", True),
        ("filigran/alpine-python-fips:python3.12", True),
        ("registry.access.redhat.com/ubi9/ubi-minimal", True),
        # Their entry point, volumes or ONBUILD triggers are not known (the UBI
        # python images set an ENTRYPOINT and a WORKDIR).
        ("registry.access.redhat.com/ubi9/python-312", False),
        ("ghcr.io/example/connector-base:1", False),
    ],
)
def test_base_images_of_the_final_stage(tmp_path, base, covered):
    dockerfile = (
        f'FROM {base}\nCOPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n'
    )
    image = single(tmp_path, {"Dockerfile": dockerfile})
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "dockerfile, covered",
    [
        # The files of an image whose content is not known may hold a wrapper
        # named after python.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            "COPY --from=ghcr.io/example/tools:1 /bin/python3 /usr/local/bin/\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            False,
        ),
        (
            "FROM node:20 AS tools\nFROM python:3.12-alpine\nCOPY src /opt/src\n"
            "COPY --from=tools /usr/local/bin/ /usr/local/bin/\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            False,
        ),
        # Copilot review of 04:56 UTC: in a stage built on such an image, even
        # the files of the model may have been rewritten by its programs.
        (
            "FROM ghcr.io/example/base:1 AS builder\nCOPY src /opt/src\n"
            "RUN python3 -m compileall /opt/src\n"
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            "COPY --from=builder /opt/src/.connector_version.json /opt/src/.connector_version.json\n"
            'CMD ["python3", "/opt/src/main.py"]\n',
            False,
        ),
        # A reviewed image: the uv binaries.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/src\n"
            "COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/\n"
            'RUN uv venv /opt/venv\nCMD ["python3", "/opt/src/main.py"]\n',
            True,
        ),
    ],
)
def test_copies_from_images_whose_content_is_not_known(tmp_path, dockerfile, covered):
    image = single(tmp_path, {"Dockerfile": dockerfile})
    assert image.covered is covered, image.reason


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
        # Copilot review of 04:10 UTC: a COPY into a directory mkdir created.
        (
            "FROM python:3.12-alpine\nENV PATH=/opt/tools:$PATH\nCOPY src /opt/sample\n"
            "RUN mkdir -p /opt/tools\nCOPY --chmod=755 python3 /opt/tools\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {"python3": ENV_WRAPPER},
        ),
        # Copilot review of 03:33 UTC: wildcard moves and links, a file of a
        # known image under another name, a RUN mount.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY wrapper.sh /tmp/tools/python3\n"
            'RUN mv /tmp/tools/* /usr/local/bin/\nCMD ["python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": ENV_WRAPPER},
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY wrapper.sh /tmp/tools/python3\n"
            'RUN ln -sf /tmp/tools/* /usr/local/bin/\nCMD ["python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": ENV_WRAPPER},
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY --from=python:3.12-alpine /bin/sh /usr/local/bin/python3\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {},
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "RUN --mount=type=bind,source=wrapper.sh,target=/usr/local/bin/python3 "
            'python3 -m compileall /opt/sample\nCMD ["python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": "#!/bin/sh\nrm -rf /opt/sample\n"},
        ),
        # Copilot review of 03:16 UTC: what lies below a moved or linked
        # directory, a download under a bare name, an ADD archive, and the
        # unknown directories a stage copy takes.
        (
            "FROM python:3.12-alpine\nENV PATH=/opt/tools:$PATH\nCOPY src /opt/sample\n"
            "COPY wrapper.sh /tmp/tools/python3\nRUN mv /tmp/tools /opt/tools\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": ENV_WRAPPER},
        ),
        (
            "FROM python:3.12-alpine\nENV PATH=/opt/tools:$PATH\nCOPY src /opt/sample\n"
            "COPY wrapper.sh /tmp/tools/python3\nRUN ln -s /tmp/tools /opt/tools\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": ENV_WRAPPER},
        ),
        (
            "FROM python:3.12-alpine\nENV PATH=/opt/tools:$PATH\nCOPY src /opt/sample\n"
            "WORKDIR /opt/tools\nRUN curl -o python3 https://example.com/w && chmod 755 python3\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {},
        ),
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nADD tools.tar /usr/local/bin/\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {"tools.tar": tar_archive("python3")},
        ),
        (
            "FROM python:3.12-alpine AS builder\n"
            "RUN git clone https://example.com/tools.git /out\n"
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY --from=builder /out/ /usr/local/bin/\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {},
        ),
        # time is a program for sh.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY wrapper.sh /usr/local/bin/time\n"
            "CMD time python3 /opt/sample/main.py\n",
            {"wrapper.sh": ENV_WRAPPER},
        ),
        # A copy below a link the build created writes where the link points.
        (
            "FROM python:3.12-alpine\nRUN mkdir /tmp/x && ln -s /tmp/x /opt/sample\n"
            "COPY src /opt/sample\nRUN rm -f /tmp/x/.connector_version.json\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {},
        ),
        # Copilot review of 03:01 UTC: the interpreter line of a script, with
        # its path or through env.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY wrapper.sh /opt/tools/python3\n"
            'COPY run.py /opt/sample/run.py\nCMD ["/opt/sample/run.py"]\n',
            {"wrapper.sh": ENV_WRAPPER, "run.py": "#!/opt/tools/python3\n"},
        ),
        (
            "FROM python:3.12-alpine\nENV PATH=/opt/tools:$PATH\nCOPY src /opt/sample\n"
            "COPY wrapper.sh /opt/tools/python3\n"
            'COPY run.py /opt/sample/run.py\nCMD ["/opt/sample/run.py"]\n',
            {"wrapper.sh": ENV_WRAPPER, "run.py": "#!/usr/bin/env python3\n"},
        ),
        # Copilot review of 03:01 UTC: a clone brings files the model does not know.
        (
            "FROM python:3.12-alpine\nENV PATH=/opt/tools:$PATH\nCOPY src /opt/sample\n"
            "RUN git clone --depth 1 https://example.com/tools.git /opt/tools\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {},
        ),
        # Copilot review of 02:45 UTC: the program of find -exec, by path or on PATH.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY clean.sh /opt/tools/cat\n"
            "RUN find /tmp -maxdepth 0 -exec /opt/tools/cat {} \\;\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {"clean.sh": "#!/bin/sh\nrm -f /opt/sample/.connector_version.json\n"},
        ),
        (
            "FROM python:3.12-alpine\nENV PATH=/opt/tools:$PATH\nCOPY src /opt/sample\n"
            "COPY clean.sh /opt/tools/cat\nRUN find /tmp -maxdepth 0 -exec cat {} +\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {"clean.sh": "#!/bin/sh\nrm -f /opt/sample/.connector_version.json\n"},
        ),
        # Copilot review of 02:45 UTC: a file a builder stage wrote keeps an
        # unknown content where COPY --from puts it.
        (
            "FROM python:3.12-alpine AS builder\n"
            "RUN echo 'rm -rf /opt/sample' > /tmp/python3 && chmod 755 /tmp/python3\n"
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY --from=builder /tmp/python3 /usr/local/bin/python3\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {},
        ),
        (
            "FROM python:3.12-alpine AS builder\n"
            "RUN mkdir -p /out && echo 'rm -rf /opt/sample' > /out/python3\n"
            "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
            "COPY --from=builder /out/ /usr/local/bin/\n"
            'CMD ["python3", "/opt/sample/main.py"]\n',
            {},
        ),
        # Copilot review of 02:45 UTC: sudo in the start command.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nWORKDIR /opt/sample\n"
            "CMD sudo --chdir=/tmp python3 main.py\n",
            {},
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
        # Copilot review of 05:48 UTC: the SHELL of a shell-form HEALTHCHECK.
        (
            "FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY --chmod=755 wrapper.sh /opt/sh\n"
            'SHELL ["/opt/sh", "-c"]\nHEALTHCHECK CMD true\nCMD ["python3", "/opt/sample/main.py"]\n',
            {"wrapper.sh": ENV_WRAPPER},
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


@pytest.mark.parametrize(
    "files, reason",
    [
        # Copilot review of 03:33 UTC: a stage built on another may keep its
        # ARG values.
        (
            {
                "Dockerfile": (
                    "FROM python:3.12-alpine AS parent\nARG APP=/opt/src\nCOPY src /opt/src\n"
                    'FROM parent\nRUN rm -f "${APP:-/tmp}/.connector_version.json"\n'
                    'CMD ["python3", "/opt/src/main.py"]\n'
                )
            },
            "not supported: deleted path '${APP:-/tmp}/.connector_version.json' uses a variable or a command the build does not define",
        ),
        # Copilot review of 03:33 UTC: in COPY sources ** is two *, as in Go's
        # filepath.Match.
        (
            {
                "Dockerfile": (
                    "FROM python:3.12-alpine\nCOPY src/**/*.json /opt/app/\n"
                    'COPY src/main.py /opt/app/\nCMD ["python3", "/opt/app/main.py"]\n'
                ),
                "src/data/config.json": "{}",
            },
            "no COPY carries a stamp into the final image",
        ),
        # Copilot review of 03:33 UTC: setup.py runs, whatever package pip finds.
        (
            {
                "Dockerfile": (
                    "FROM python:3.12-alpine\nCOPY src /opt/build\nRUN pip install /opt/build\n"
                    'CMD ["python3", "/opt/build/main.py"]\n'
                ),
                "src/setup.py": "import os\nos.remove('.connector_version.json')\n",
            },
            "not supported: packaging declared in setup.py",
        ),
    ],
)
def test_build_semantics_of_docker_and_pip(tmp_path, files, reason):
    assert single(tmp_path, files).reason == reason


@pytest.mark.parametrize(
    "run, extra, covered",
    [
        # The local packages of a requirement file are installed too, and run
        # their packaging code, editable or not.
        (
            # ./tools is read from the working directory of pip.
            "WORKDIR /opt/src\nRUN pip install -r requirements.txt",
            {"src/requirements.txt": "requests\n./tools\n", "src/tools/setup.py": ""},
            False,
        ),
        (
            "RUN pip install -e /opt/src/tools",
            {"src/tools/setup.py": ""},
            False,
        ),
        (
            "RUN pip install -r /opt/src/requirements.txt",
            {"src/requirements.txt": "requests\n"},
            True,
        ),
        # Copilot review of 05:25 UTC: attached option values, on the command
        # line and in requirement files.
        ("RUN pip install -e/opt/src/tools", {"src/tools/setup.py": ""}, False),
        (
            "WORKDIR /opt/src\nRUN pip install -r requirements.txt",
            {"src/requirements.txt": "-e./tools\n", "src/tools/setup.py": ""},
            False,
        ),
        (
            "WORKDIR /opt/src\nRUN pip install -rrequirements.txt",
            {
                "src/requirements.txt": "-rnested.txt\n",
                "src/nested.txt": "--editable=./tools\n",
                "src/tools/setup.py": "",
            },
            False,
        ),
        # A local wheel or source archive: its content is not read.
        ("RUN pip install /opt/src/dist/sample-1.0-py3-none-any.whl", {}, False),
        # Copilot review of 05:48 UTC: pip takes an archive name as a local file,
        # without a slash too, on the command line and in a requirement file.
        (
            "WORKDIR /opt/src\nRUN pip install payload.tar.gz",
            {"src/payload.tar.gz": ""},
            False,
        ),
        (
            "WORKDIR /opt/src\nRUN pip install Payload.ZIP",
            {"src/Payload.ZIP": ""},
            False,
        ),
        (
            "WORKDIR /opt/src\nRUN pip install -r requirements.txt",
            {"src/requirements.txt": "payload.tbz\n", "src/payload.tbz": ""},
            False,
        ),
        # A requirement file the model cannot read.
        ("RUN pip install -r /usr/share/requirements.txt", {}, False),
        # A bind mount of the context shows its files at the target.
        (
            "RUN --mount=type=bind,source=src/requirements.txt,target=/tmp/requirements.txt "
            "pip install -r /tmp/requirements.txt",
            {"src/requirements.txt": "requests\n"},
            True,
        ),
        (
            "RUN --mount=type=cache,target=/tmp/requirements pip install -r /tmp/requirements/all.txt",
            {},
            False,
        ),
    ],
)
def test_pip_install_targets(tmp_path, run, extra, covered):
    files = {
        "Dockerfile": (
            f"FROM python:3.12-alpine\nCOPY src /opt/src\n{run}\n"
            'CMD ["python3", "/opt/src/main.py"]\n'
        ),
        **extra,
    }
    assert single(tmp_path, files).covered is covered


def test_add_extracts_an_archive_whatever_its_name(tmp_path):
    # Docker recognises a tar archive, compressed or not, by its content.
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nCOPY src /opt/src\nADD payload.bin /opt/src/\n"
                'CMD ["python3", "/opt/src/main.py"]\n'
            )
        },
    )
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        member = tarfile.TarInfo(".connector_version.json")
        archive.addfile(member, io.BytesIO(b""))
    (connector / "payload.bin").write_bytes(payload.getvalue())
    [image] = result(tmp_path, connector)
    assert not image.covered
    # Copilot review of 07:32 UTC: by content only - a tar header without the
    # ustar magic and a zstd stream are archives, compressed text is a file.
    old_tar = bytearray(tar_archive(".connector_version.json"))
    old_tar[257:265] = bytes(8)
    old_tar[148:156] = b" " * 8
    old_tar[148:155] = b"%06o\x00" % sum(old_tar[:512])
    (connector / "payload.bin").write_bytes(bytes(old_tar))
    [image] = result(tmp_path, connector)
    assert not image.covered
    (connector / "payload.bin").write_bytes(b"\x28\xb5\x2f\xfd" + bytes(16))
    [image] = result(tmp_path, connector)
    assert not image.covered
    (connector / "payload.bin").write_bytes(gzip.compress(b"not an archive"))
    [image] = result(tmp_path, connector)
    assert image.covered, image.reason
    (connector / "payload.bin").write_bytes(b"not an archive")
    [image] = result(tmp_path, connector)
    assert image.covered, image.reason


def test_stamp_written_through_a_link(tmp_path):
    # Copilot review of 03:54 UTC: the build step writes through the link.
    connector = make_connector(
        tmp_path,
        {"Dockerfile": ALPINE_SRC, "real/main.py": ""},
    )
    for name in ("main.py",):
        (connector / "src" / name).unlink()
    (connector / "src").rmdir()
    try:
        (connector / "src").symlink_to("real", target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links cannot be created here")
    [image] = result(tmp_path, connector)
    assert image.reason == (
        "not supported: the stamp src/.connector_version.json is written through a symbolic link"
    )


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
    "instructions, reason",
    [
        # Copilot review of 05:48 UTC: COPY writes through a link of the build.
        (
            "RUN ln -s /usr/local/bin /alias\nCOPY wrapper.sh /alias/python3",
            "not supported: COPY to /alias/python3 goes through the link /alias the build created",
        ),
        (
            "RUN ln -s /usr/local/bin /alias\nCOPY wrapper.sh /alias/",
            "not supported: COPY to /alias/wrapper.sh goes through the link /alias the build created",
        ),
        (
            "RUN ln -s /usr/local/bin /alias\nCOPY wrapper.sh /opt/wrapper.sh",
            "stamp at /opt/sample/.connector_version.json",
        ),
        # Copilot review of 05:48 UTC: a link a stage created stays a link in the
        # stage that copies it.
        (
            "RUN ln -s /opt/sample /opt/sample/link\nFROM python:3.12-alpine\n"
            "COPY --from=0 /opt/sample /opt/sample\n"
            "RUN rm -f /opt/sample/link/.connector_version.json",
            "not supported: /opt/sample/link/.connector_version.json goes through the link"
            " /opt/sample/link the build created",
        ),
        (
            "RUN ln -s /opt/sample /opt/sample/link\nFROM python:3.12-alpine\n"
            "COPY --from=0 /opt/sample /opt/sample",
            "stamp at /opt/sample/.connector_version.json",
        ),
    ],
)
def test_copies_through_links_of_the_build(tmp_path, instructions, reason):
    files = {
        "Dockerfile": (
            f"FROM python:3.12-alpine\nCOPY src /opt/sample\n{instructions}\n"
            'CMD ["python3", "/opt/sample/main.py"]\n'
        ),
        "wrapper.sh": ENV_WRAPPER,
    }
    assert single(tmp_path, files).reason == reason


def test_operations_through_a_link_of_the_context(tmp_path):
    # Copilot review of 05:48 UTC: a copied link of the context is a link whose
    # target is not modelled.
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nCOPY src /opt/app\n"
                "RUN rm -f /opt/app/link/.connector_version.json\n"
                'CMD ["python3", "/opt/app/main.py"]\n'
            )
        },
    )
    try:
        (connector / "src/link").symlink_to(".", target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links cannot be created here")
    [image] = result(tmp_path, connector)
    assert image.reason == (
        "not supported: /opt/app/link/.connector_version.json goes through the link"
        " /opt/app/link the build created"
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


@pytest.mark.parametrize(
    "lines, covered",
    [
        # Copilot review of 11:49 UTC: a list whose operator ends a line goes on
        # with the next line, so the assignment there may not run.
        ("APP=/opt/sample\nfalse &&\nAPP=/tmp\n", False),
        ("APP=/opt/sample\ntrue ||\nAPP=/tmp\n", False),
        ("APP=/opt/sample\nfalse && APP=/tmp\n", False),
        ("APP=/opt/sample\nfalse\nAPP=/tmp\n", True),
        ("APP=/tmp\necho ready |\ncat > /dev/null\n", True),
    ],
)
def test_list_continued_on_the_next_line(tmp_path, lines, covered):
    files = {
        "Dockerfile": 'FROM python:3.12-alpine\nCOPY src /opt/sample\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
        "entrypoint.sh": f'#!/bin/sh\n{lines}rm -f "$APP/.connector_version.json"\n'
        "cd /opt/sample\nexec python3 main.py\n",
    }
    assert single(tmp_path, files).covered is covered


@pytest.mark.parametrize(
    "builder, covered",
    [
        # Copilot review of 13:37 UTC: a COPY --from of a directory carries the
        # files touch created there; an empty one shadows the program it names.
        ("RUN mkdir /out && touch /out/python3 && chmod 755 /out/python3", False),
        ("RUN mkdir /out && touch -- /out/python3", False),
        ("RUN mkdir /out && touch -d 2020-01-01 /out/python3", False),
        ("RUN mkdir /out && touch /out/marker", True),
        ("RUN mkdir /out && touch -c /out/python3", True),
        ("RUN mkdir /out && touch -r /etc/os-release /out/marker", True),
    ],
)
def test_a_stage_copy_carries_the_files_touch_created(tmp_path, builder, covered):
    files = {
        "Dockerfile": f"FROM python:3.12-alpine AS builder\n{builder}\n"
        "FROM python:3.12-alpine\nCOPY src /opt/src\nCOPY --from=builder /out/ /usr/local/bin/\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason


def stamp_copied_after(tmp_path, run):
    files = {
        "Dockerfile": f"FROM python:3.12-alpine\nCOPY src/main.py /opt/main.py\nRUN {run}\n"
        "COPY src/.connector_version.json /opt/.connector_version.json\n"
        'CMD ["python3", "/opt/main.py"]\n',
    }
    return single(tmp_path, files)


@pytest.mark.parametrize(
    "command",
    [
        # Copilot review of 14:15 UTC: what find -exec mkdir or touch creates is
        # in the model, as when the build runs the command itself.
        "mkdir /opt/.connector_version.json",
        "mkdir -p /opt/cache",
        "touch /usr/local/bin/python3",
        "touch /opt/marker",
    ],
)
def test_find_exec_creates_what_the_command_creates(tmp_path, command):
    direct = stamp_copied_after(tmp_path / "direct", command)
    found = stamp_copied_after(
        tmp_path / "found", f"find /tmp -maxdepth 0 -exec {command} \\;"
    )
    assert (found.covered, found.reason) == (direct.covered, direct.reason)


@pytest.mark.parametrize(
    "run, covered",
    [
        # The COPY puts the stamp inside the directory find created.
        ("find /tmp -maxdepth 0 -exec mkdir /opt/.connector_version.json \\;", False),
        ("find /tmp -maxdepth 0 -exec mkdir -p /opt/cache \\;", True),
        ("find /tmp -maxdepth 0 -exec mkdir {}/x \\;", False),
        ("find /tmp -maxdepth 0 -execdir touch marker \\;", False),
    ],
)
def test_find_exec_mkdir_and_touch(tmp_path, run, covered):
    image = stamp_copied_after(tmp_path, run)
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "removal, covered",
    [
        # Copilot review of 14:15 UTC: ~NAME is the home directory of NAME in
        # the account database of the image, which the model does not read.
        ("rm -f ~root/.connector_version.json", False),
        ("rm -f ~+/.connector_version.json", False),
        ("rm -f ~/.connector_version.json", False),
        ("rm -f ~/other.json", True),
    ],
)
def test_tilde_prefixes(tmp_path, removal, covered):
    files = {
        "Dockerfile": f"FROM python:3.12-alpine\nCOPY src /root\nRUN {removal}\n"
        'CMD ["python3", "/root/main.py"]\n',
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason
    if removal.startswith("rm -f ~root") or removal.startswith("rm -f ~+"):
        assert "tilde prefix" in image.reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # Copilot review of 15:50 UTC: a builtin name given as a path, or started
        # by env, nohup or time, runs a program of the image, not the builtin.
        ("/opt/tools/export", False),
        ("/opt/tools/unset X", False),
        ("export X=1; unset X", True),
        ("cd /tmp; rm -f .connector_version.json", True),
        ("env cd /tmp; rm -f .connector_version.json", False),
        ("nohup cd /tmp; rm -f .connector_version.json", False),
    ],
)
def test_a_builtin_name_runs_the_builtin_only_as_a_bare_name(tmp_path, run, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\n"
        "COPY clean.sh /opt/tools/export\nCOPY clean.sh /opt/tools/unset\n"
        f"WORKDIR /opt/src\nRUN {run}\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
        "clean.sh": "#!/bin/sh\nrm -f /opt/src/.connector_version.json\n",
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # Copilot review of 16:18 UTC: a .. after a link climbs from the target
        # of the link, and the symbolic link of an option cluster (ln -s, -sf)
        # resolves from its own directory.
        (
            "ln -s /opt/src/nested /alias && rm -f /alias/../.connector_version.json",
            False,
        ),
        ("rm -f /opt/src/nested/../other.json", True),
        (
            "mkdir -p /opt/alias && ln -s ../src /opt/alias/app;"
            " rm -f /opt/alias/app/.connector_version.json",
            False,
        ),
        (
            "mkdir -p /opt/alias && ln -sf ../src /opt/alias/app;"
            " rm -f /opt/alias/app/.connector_version.json",
            False,
        ),
        (
            "mkdir -p /opt/alias && ln -s ../src /opt/alias/app; rm -f /opt/alias/other.json",
            True,
        ),
    ],
)
def test_links_and_parent_directories(tmp_path, run, covered):
    files = {
        "Dockerfile": f"FROM python:3.12-alpine\nCOPY src /opt/src\nRUN {run}\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
        "src/nested/keep.txt": "",
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason


def test_a_connector_path_without_an_image_fails_the_check(tmp_path, capsys):
    # Copilot review of 16:18 UTC: a requested path that names no image would
    # report a check that never ran.
    make_connector(tmp_path, {"Dockerfile": ALPINE_SRC})
    assert check.main(["--root", str(tmp_path), "external-import/sample"]) == 0
    with pytest.raises(SystemExit) as error:
        check.main(
            [
                "--root",
                str(tmp_path),
                "external-import/sample",
                "external-import/misspelled",
            ]
        )
    assert error.value.code == 2
    assert "external-import/misspelled" in capsys.readouterr().err


def test_touch_keeps_the_content_of_a_file_of_the_model(tmp_path):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\n"
        "RUN touch /opt/src/.connector_version.json /opt/src\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
    }
    image = single(tmp_path, files)
    assert image.covered, image.reason


@pytest.mark.parametrize(
    "removal, covered",
    [
        # Copilot review of 12:40 UTC: the directory a recursive rm removed is
        # gone, the cd fails and the shell stays in /opt/app.
        ("rm -rf /tmp/gone", False),
        ("rm -r -- /tmp/gone", False),
        ("rm -f /tmp/gone", True),
    ],
)
def test_cd_into_a_removed_directory_in_an_entry_script(tmp_path, removal, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/app\nRUN mkdir /tmp/gone\n"
        'COPY entrypoint.sh /\nWORKDIR /opt/app\nENTRYPOINT ["/entrypoint.sh"]\n',
        "entrypoint.sh": f"#!/bin/sh\n{removal}\ncd /tmp/gone\n"
        "rm -f .connector_version.json\nexec python3 /opt/app/main.py\n",
    }
    assert single(tmp_path, files).covered is covered


@pytest.mark.parametrize(
    "line, reason",
    [
        ("#!/usr/bin/env python3", "stamp at /opt/sample/.connector_version.json"),
        # Copilot review of 09:00 UTC: env -S runs python with arguments of its
        # own, here inline code instead of the script.
        (
            "#!/usr/bin/env -S python3 -c 'import pycti'",
            "not supported: interpreter line '#!/usr/bin/env -S python3 -c 'import pycti''",
        ),
        (
            "#!/usr/bin/env PYTHONSAFEPATH=1 python3",
            "not supported: interpreter line '#!/usr/bin/env PYTHONSAFEPATH=1 python3'",
        ),
        # Copilot review of 15:50 UTC: python started by the kernel with an
        # argument of the line may run another module than the script.
        ("#!/usr/local/bin/python3", "stamp at /opt/sample/.connector_version.json"),
        (
            "#!/usr/local/bin/python3 -mother",
            "not supported: interpreter line '#!/usr/local/bin/python3 -mother'",
        ),
        (
            "#!/usr/local/bin/python3 -u",
            "not supported: interpreter line '#!/usr/local/bin/python3 -u'",
        ),
    ],
)
def test_env_interpreter_line(tmp_path, line, reason):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/sample\n"
        'COPY run.py /opt/sample/run.py\nWORKDIR /tmp\nCMD ["/opt/sample/run.py"]\n',
        "run.py": line + "\n",
    }
    assert single(tmp_path, files).reason == reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # Copilot review of 18:58 UTC: curl --output-dir places -o and -O, in
        # either order, and not the headers curl writes.
        (
            "curl --output-dir /opt/src -o .connector_version.json https://example.com/x",
            False,
        ),
        (
            "curl -o .connector_version.json --output-dir /opt/src https://example.com/x",
            False,
        ),
        (
            "curl --output-dir=/opt/src -O https://example.com/.connector_version.json",
            False,
        ),
        (
            "cd /opt/src && curl --output-dir /tmp -o .connector_version.json https://example.com/x",
            True,
        ),
        (
            "cd /opt/src && curl --output-dir /tmp -D .connector_version.json https://example.com/x",
            False,
        ),
        (
            "curl --output-dir /tmp -o /opt/src/.connector_version.json https://example.com/x",
            False,
        ),
        (
            "wget -P /tmp -O /opt/src/.connector_version.json https://example.com/x",
            False,
        ),
    ],
)
def test_curl_output_directory(tmp_path, run, covered):
    files = {
        "Dockerfile": f"FROM python:3.12-alpine\nCOPY src /opt/src\nRUN {run}\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # Copilot review of 18:58 UTC: a configuration file named for one
        # command, by a prefix assignment or by env.
        ("WGETRC=/tmp/download.conf wget -O /tmp/x https://example.com/x", False),
        ("env WGETRC=/tmp/download.conf wget -O /tmp/x https://example.com/x", False),
        (
            "SYSTEM_WGETRC=/tmp/download.conf wget -O /tmp/x https://example.com/x",
            False,
        ),
        ("CURL_HOME=/tmp curl -o /tmp/x https://example.com/x", False),
        ("wget -O /tmp/x https://example.com/x", True),
    ],
)
def test_downloader_configuration_set_for_one_command(tmp_path, run, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\n"
        f"COPY download.conf /tmp/download.conf\nRUN {run}\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
        "download.conf": "output_document = /opt/src/.connector_version.json\n",
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # Copilot review of 18:58 UTC: a PYTHONPATH the model does not resolve
        # may put any module first.
        (
            "if true; then export PYTHONPATH=/opt/tools; fi; python3 -m pip install requests",
            False,
        ),
        (
            "if true; then export PYTHONPATH=/opt/other; fi; python3 -m compileall -q /opt/src",
            False,
        ),
        ("export PYTHONPATH=/opt/tools; python3 -m pip install requests", False),
        ("export PYTHONPATH=/opt/other; python3 -m pip install requests", True),
        # Copilot review of 18:58 UTC: at startup, whatever it runs, python
        # imports sitecustomize from PYTHONPATH, not from the working directory.
        ("export PYTHONPATH=/opt/hooks; python3 -m compileall -q /opt/src", False),
        ("export PYTHONPATH=/opt/hooks; pip install requests", False),
        ("PYTHONPATH=/opt/hooks python3 -m compileall -q /opt/src", False),
        ("cd /opt/hooks && python3 -m compileall -q /opt/src", True),
        ("python3 -m compileall -q /opt/src", True),
    ],
)
def test_python_search_path_at_build_time(tmp_path, run, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\n"
        "COPY remove.py /opt/tools/pip.py\nCOPY remove.py /opt/hooks/sitecustomize.py\n"
        f"RUN {run}\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
        "remove.py": "import os\nos.remove('/opt/src/.connector_version.json')\n",
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "target, covered",
    [
        # Copilot review of 18:58 UTC: the startup files of site-packages.
        ("/usr/local/lib/python3.12/site-packages/sitecustomize.py", False),
        ("/usr/local/lib/python3.12/site-packages/remove.pth", False),
        ("/usr/local/lib/python3.12/site-packages/remove/__init__.py", True),
    ],
)
def test_startup_files_of_site_packages_at_build_time(tmp_path, target, covered):
    files = {
        "Dockerfile": f"FROM python:3.12-alpine\nCOPY src /opt/src\nCOPY remove.py {target}\n"
        "RUN python3 -m compileall -q /opt/src\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
        "remove.py": "import os\nos.remove('/opt/src/.connector_version.json')\n",
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "command, covered",
    [
        # Copilot review of 18:58 UTC: a .. after a link in the path of the
        # program started climbs from the target of the link.
        ('["python3", "/opt/app/alias/../main.py"]', False),
        ('["sh", "/opt/app/alias/../start.sh"]', False),
        ('["/opt/app/alias/../run.py"]', False),
        ('["python3", "/opt/app/sub/../main.py"]', True),
        ('["sh", "/opt/app/sub/../start.sh"]', True),
    ],
)
def test_entry_point_after_a_link(tmp_path, command, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/app\n"
        "RUN mkdir -p /opt/deep/a/b/c/d/e/sub /opt/app/sub"
        " && ln -s /opt/deep/a/b/c/d/e/sub /opt/app/alias\n"
        f"WORKDIR /srv\nCMD {command}\n",
        "src/start.sh": "#!/bin/sh\nexec python3 /opt/app/main.py\n",
        "src/run.py": "#!/usr/local/bin/python3\n",
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason
    if not covered:
        assert "climbs out of the link /opt/app/alias the build created" in image.reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # Copilot review of 21:00 UTC: a sourced file without a '/' is searched
        # on PATH, not in the working directory.
        (". setup.sh", False),
        ("source setup.sh", False),
        (". ./setup.sh", True),
    ],
)
def test_sourced_file_without_a_slash(tmp_path, run, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\n"
        "COPY remove.sh /usr/local/bin/setup.sh\nWORKDIR /opt/src\n"
        f'RUN {run}\nCMD ["python3", "/opt/src/main.py"]\n',
        "src/setup.sh": "true\n",
        "remove.sh": "rm -f /opt/src/.connector_version.json\n",
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason
    if not covered:
        assert "searched on PATH" in image.reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # Copilot review of 21:00 UTC: a mkdir in a branch may not run, so a cd
        # into its directory may fail and leave the shell where it was.
        (
            "if false; then mkdir /tmp/gone; fi; cd /tmp/gone; rm -f .connector_version.json",
            False,
        ),
        (
            "test -d /tmp/gone || mkdir /tmp/gone; cd /tmp/gone; rm -f .connector_version.json",
            False,
        ),
        ("mkdir /tmp/gone; cd /tmp/gone; rm -f .connector_version.json", True),
        # Copilot review of 21:28 UTC: a mkdir after && may not run either; after
        # the list its directory may be missing, within the list it exists.
        (
            "false && mkdir /tmp/gone; cd /tmp/gone; rm -f .connector_version.json",
            False,
        ),
        (
            "true && mkdir /tmp/gone && cd /tmp/gone && rm -f .connector_version.json",
            True,
        ),
        # A pipeline part or a background job may not have created it.
        ("mkdir /tmp/gone | true; cd /tmp/gone; rm -f .connector_version.json", False),
        ("mkdir /tmp/gone & cd /tmp/gone; rm -f .connector_version.json", False),
        # Without -p, mkdir fails when the parent directory is missing.
        ("mkdir /tmp/a/b; cd /tmp/a/b; rm -f .connector_version.json", False),
        ("mkdir -p /tmp/a/b; cd /tmp/a/b; rm -f .connector_version.json", True),
        ("mkdir /tmp/a /tmp/a/b; cd /tmp/a/b; rm -f .connector_version.json", True),
    ],
)
def test_cd_into_a_directory_of_a_conditional_mkdir(tmp_path, run, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\nWORKDIR /opt/src\n"
        f'RUN {run}\nCMD ["python3", "/opt/src/main.py"]\n',
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason
    if not covered:
        assert "unknown working directory" in image.reason


@pytest.mark.parametrize(
    "run, covered",
    [
        # An exit after &&, in a pipeline part or in a background job may leave
        # the script going on.
        ("false && exit 0; rm -f .connector_version.json", False),
        ("true | exit 0; rm -f .connector_version.json", False),
        ("exit 0 & rm -f .connector_version.json", False),
        ("exit 0; rm -f .connector_version.json", True),
    ],
)
def test_exit_that_may_not_end_the_script(tmp_path, run, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\nWORKDIR /opt/src\n"
        f'RUN {run}\nCMD ["python3", "/opt/src/main.py"]\n',
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason


@pytest.mark.parametrize(
    "mkdir, covered",
    [
        # Where a copy lands depends on whether the directory exists.
        ("if false; then mkdir /opt/app; fi", False),
        ("mkdir /opt/app", True),
        # The build fails unless the last list of the RUN succeeds: when that list
        # is a plain && list, every command of it ran.
        ("true && mkdir -p /opt/app", True),
        ("false && mkdir /opt/app; true", False),
        ("false && mkdir /opt/app || true", False),
    ],
)
def test_copy_into_a_directory_of_a_conditional_mkdir(tmp_path, mkdir, covered):
    files = {
        "Dockerfile": f"FROM python:3.12-alpine\nRUN {mkdir}\n"
        "COPY src/main.py /opt/app\nCOPY src/.connector_version.json /opt/app\n"
        'CMD ["python3", "/opt/app/main.py"]\n',
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason
    if not covered:
        assert "a mkdir that may not run" in image.reason


@pytest.mark.parametrize(
    "removal, covered",
    [
        # Copilot review of 21:00 UTC: a wildcard expands through the links it
        # reaches.
        ("rm -f /opt/src/*/.connector_version.json", False),
        ("rm -f /opt/src/l?nk/.connector_version.json", False),
        ("rm -f /opt/src/*.pyc", True),
    ],
)
def test_wildcard_through_a_link_of_the_build(tmp_path, removal, covered):
    files = {
        "Dockerfile": "FROM python:3.12-alpine\nCOPY src /opt/src\n"
        f"RUN ln -s /opt/src /opt/src/link && {removal}\n"
        'CMD ["python3", "/opt/src/main.py"]\n',
    }
    image = single(tmp_path, files)
    assert image.covered is covered, image.reason
    if not covered:
        assert "goes through the link /opt/src/link" in image.reason


def test_wildcard_through_a_link_of_the_context(tmp_path):
    # Copilot review of 21:00 UTC: with src/link -> ., the wildcard expands
    # through /opt/src/link to the stamp.
    connector = make_connector(
        tmp_path,
        {
            "Dockerfile": (
                "FROM python:3.12-alpine\nCOPY src /opt/src\n"
                "RUN rm -f /opt/src/*/.connector_version.json\n"
                'CMD ["python3", "/opt/src/main.py"]\n'
            )
        },
    )
    try:
        (connector / "src/link").symlink_to(".", target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links cannot be created here")
    [image] = result(tmp_path, connector)
    assert image.reason == (
        "not supported: /opt/src/*/.connector_version.json goes through the link"
        " /opt/src/link the build created"
    )


@pytest.mark.parametrize(
    "base",
    [
        # Copilot review of 21:00 UTC: an onbuild image runs build triggers, and
        # the UBI images other than ubi9/ubi-minimal are not the documented base.
        "python:3.6-onbuild",
        "docker.io/library/python:3.6-onbuild",
        "registry.access.redhat.com/ubi9/ubi-init",
        "registry.access.redhat.com/ubi9/ubi-micro",
        "registry.access.redhat.com/ubi9/ubi",
        "registry.access.redhat.com/ubi8/ubi-minimal",
    ],
)
def test_base_images_outside_the_reviewed_ones(tmp_path, base):
    dockerfile = (
        f'FROM {base}\nCOPY src /opt/src\nCMD ["python3", "/opt/src/main.py"]\n'
    )
    image = single(tmp_path, {"Dockerfile": dockerfile})
    assert not image.covered, image.reason


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
