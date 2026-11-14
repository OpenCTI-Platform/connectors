#!/usr/bin/env python3
"""Check that every connector image carries its identity stamp where pycti reads it.

The shared image build (step "Write connector version stamp" of
.github/actions/build-connector-image) writes ``.connector_version.json``
(version and catalog slug) at the connector root and in its code directory
(``src/``, or the top-level package of a packaged connector). At registration,
pycti (``pycti/connector/opencti_connector_build.py``) looks for that file in
the directory of the entry point, of ``sys.path[0]`` and of the working
directory, each with up to four parent directories. The platform then shows
the connector with the logo and the title of its catalog entry.

For every image the pipeline builds (the connector ``Dockerfile``, its
``Dockerfile_fips``, and the shared ``Dockerfile_ubi9`` for the connectors of
``.github/ubi9-connectors.json`` with their ``.build.env``) and for the
connector templates, this script reads the stages, WORKDIR, ENV / ARG,
COPY / ADD, ``rm`` in RUN and CMD / ENTRYPOINT, the ``.dockerignore``, the
entry-point shell script and the packaging, and tells whether a stamp lands in
a directory pycti reads.

Usage:
    python3 .github/scripts/check_connector_stamp.py
        Check every connector; exit 1 when an image cannot carry the stamp.
    python3 .github/scripts/check_connector_stamp.py external-import/mitre ...
        Check the given connector directories only.
"""

import argparse
import fnmatch
import json
import posixpath
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

STAMP = ".connector_version.json"
CONNECTOR_TYPES = (
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
)
UBI9_DOCKERFILE = "Dockerfile_ubi9"
UBI9_CONNECTORS = ".github/ubi9-connectors.json"
# pycti reads the anchor directory and its first four parents.
STAMP_PARENT_DEPTH = 4
# Abstract location of an installed package: the real path depends on the
# Python version of the base image, and pycti only needs the package directory.
SITE_PACKAGES = "/<site-packages>"
PYTHON_EXECUTABLE = re.compile(r"^(.*/)?python(3(\.\d+)?)?$")
SHELL_EXECUTABLE = re.compile(r"^(.*/)?(ba|da)?sh$")
VARIABLE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)


@dataclass
class Stage:
    """Image facts that matter for the stamp, per build stage."""

    workdir: str = "/"
    stamps: set = field(default_factory=set)
    # Image path -> context path of the shell scripts an entry point may run.
    scripts: dict = field(default_factory=dict)
    entrypoint: list = None
    cmd: list = None
    installs_package: bool = False
    variables: dict = field(default_factory=dict)

    def child(self):
        return Stage(
            workdir=self.workdir,
            stamps=set(self.stamps),
            scripts=dict(self.scripts),
            entrypoint=self.entrypoint,
            cmd=self.cmd,
            installs_package=self.installs_package,
            variables=dict(self.variables),
        )


@dataclass
class Result:
    image: str
    covered: bool
    reason: str


def ancestors(directory, depth=STAMP_PARENT_DEPTH):
    """The directory and its first ``depth`` parents, as pycti walks them."""
    found = [directory]
    current = directory
    for _ in range(depth):
        parent = posixpath.dirname(current)
        if parent == current:
            break
        found.append(parent)
        current = parent
    return found


def image_path(path, workdir):
    if path.startswith("/"):
        return posixpath.normpath(path)
    return posixpath.normpath(posixpath.join(workdir, path))


def stamp_code_dir(connector_dir):
    """Mirror of the STAMP_DIR computation of the build step."""
    packages = sorted(
        main.parent
        for main in connector_dir.glob("*/__main__.py")
        if main.parent.name != "src"
    )
    if packages:
        return packages[0].relative_to(connector_dir).as_posix()
    if (connector_dir / "src").is_dir():
        return "src"
    return None


def written_stamps(connector_dir):
    """Context-relative paths of the stamps the build step writes."""
    stamps = [STAMP]
    code_dir = stamp_code_dir(connector_dir)
    if code_dir:
        stamps.append(f"{code_dir}/{STAMP}")
    return stamps


def glob_regex(pattern):
    """Translate a .dockerignore glob into a regular expression."""
    out = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[" and pattern.find("]", i) != -1:
            end = pattern.find("]", i)
            out.append(pattern[i : end + 1])
            i = end
        else:
            out.append(re.escape(char))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def dockerignore_rules(connector_dir):
    path = connector_dir / ".dockerignore"
    if not path.is_file():
        return []
    rules = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        pattern = posixpath.normpath(
            (line[1:] if negated else line).strip().lstrip("/")
        )
        rules.append((negated, pattern, glob_regex(pattern)))
    return rules


def ignored_by(path, rules):
    """The .dockerignore pattern excluding ``path`` from the context, or None.

    As in Docker, the last matching rule wins and a rule matching a parent
    directory excludes its content.
    """
    parts = path.split("/")
    candidates = ["/".join(parts[: n + 1]) for n in range(len(parts))]
    verdict = None
    for negated, pattern, regex in rules:
        if any(regex.match(candidate) for candidate in candidates):
            verdict = None if negated else pattern
    return verdict


def expand(value, variables):
    """Substitute the ENV / ARG values known at this point of the build."""

    def substitute(match):
        name = match.group(1) or match.group(3)
        default = match.group(2)
        if name in variables:
            return variables[name]
        return default if default is not None else match.group(0)

    return VARIABLE.sub(substitute, value)


def assignments(arguments):
    """Key / value pairs of an ENV or ARG instruction."""
    try:
        tokens = shlex.split(arguments)
    except ValueError:
        tokens = arguments.split()
    if len(tokens) >= 2 and "=" not in tokens[0]:
        # Legacy form: ENV KEY value
        return {tokens[0]: " ".join(tokens[1:])}
    pairs = {}
    for token in tokens:
        key, sep, value = token.partition("=")
        pairs[key] = value if sep else None
    return pairs


def logical_lines(text):
    """Dockerfile instructions with their continuation lines joined."""
    lines = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        lines.append(current + stripped)
        current = ""
    if current:
        lines.append(current)
    return lines


def parse_command(value):
    """Exec form (JSON array) or shell form of CMD / ENTRYPOINT."""
    value = value.strip()
    if value.startswith("["):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except ValueError:
            pass
    return ["/bin/sh", "-c", value]


def split_copy_args(arguments):
    """Flags, sources and destination of a COPY / ADD instruction."""
    flags = {}
    rest = arguments.strip()
    while rest.startswith("--"):
        token, _, rest = rest.partition(" ")
        name, _, value = token[2:].partition("=")
        flags[name] = value if value else True
        rest = rest.strip()
    try:
        items = json.loads(rest) if rest.startswith("[") else shlex.split(rest)
    except ValueError:
        items = rest.split()
    if len(items) < 2:
        return flags, [], None
    return flags, items[:-1], items[-1]


def copy_stamps(sources, dest, flags, available, workdir):
    """Image paths of the stamps a COPY puts in the image.

    ``available`` holds the stamps the source can provide: context-relative
    paths for a COPY from the build context, absolute paths for a COPY from a
    previous stage.
    """
    from_stage = "from" in flags
    keep_parents = bool(flags.get("parents")) and not from_stage
    dest_path = image_path(dest, workdir)
    dest_is_dir = dest.endswith("/") or dest in (".", "./") or len(sources) > 1
    copied = set()
    for source in sources:
        if from_stage:
            normalized = image_path(source, "/")
        elif source in (".", "./"):
            normalized = "."
        else:
            normalized = posixpath.normpath(source.lstrip("/"))
        for stamp in available:
            if normalized in (".", "/"):
                copied.add(posixpath.join(dest_path, stamp.lstrip("/")))
            elif stamp.startswith(normalized.rstrip("/") + "/"):
                relative = (
                    stamp if keep_parents else stamp[len(normalized.rstrip("/")) + 1 :]
                )
                copied.add(posixpath.join(dest_path, relative))
            elif stamp == normalized or fnmatch.fnmatchcase(stamp, normalized):
                if keep_parents:
                    copied.add(posixpath.join(dest_path, stamp))
                elif dest_is_dir:
                    copied.add(posixpath.join(dest_path, posixpath.basename(stamp)))
                else:
                    copied.add(dest_path)
    return copied


def removed_paths(command, workdir):
    """Absolute paths a RUN command deletes with ``rm``."""
    removed = []
    cwd = workdir
    for segment in re.split(r"&&|;|\|\|", command):
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            continue
        if tokens[0] == "cd" and len(tokens) > 1:
            cwd = image_path(tokens[1], cwd)
        elif tokens[0] == "rm":
            removed.extend(
                image_path(t, cwd) for t in tokens[1:] if not t.startswith("-")
            )
    return removed


def package_ships_stamp(connector_dir):
    """A packaged connector carries the stamp into site-packages when its
    package data declares it."""
    for name in ("pyproject.toml", "setup.cfg", "setup.py", "MANIFEST.in"):
        path = connector_dir / name
        if path.is_file() and STAMP in path.read_text(encoding="utf-8"):
            return True
    return False


def build_env(connector_dir):
    """Build arguments of the UBI9 image (``.build.env``)."""
    path = connector_dir / ".build.env"
    if not path.is_file():
        return {}
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"')
    return values


def analyse_dockerfile(connector_dir, dockerfile, build_args):
    """Final stage of the image built from ``dockerfile`` with the connector
    directory as build context."""
    named = {}
    stage = Stage()
    rules = dockerignore_rules(connector_dir)
    context_stamps = [
        s for s in written_stamps(connector_dir) if not ignored_by(s, rules)
    ]
    for line in logical_lines(dockerfile.read_text(encoding="utf-8")):
        instruction, _, arguments = line.partition(" ")
        instruction = instruction.upper()
        if instruction == "FROM":
            tokens = arguments.split()
            image = next((t for t in tokens if not t.startswith("--")), "")
            stage = named[image].child() if image in named else Stage()
            if len(tokens) >= 3 and tokens[-2].upper() == "AS":
                named[tokens[-1]] = stage
        elif instruction in ("ENV", "ARG"):
            for key, value in assignments(arguments).items():
                if instruction == "ARG" and key in build_args:
                    value = build_args[key]
                if value is not None:
                    stage.variables[key] = expand(value, stage.variables)
        elif instruction == "WORKDIR":
            stage.workdir = image_path(
                expand(arguments.strip(), stage.variables), stage.workdir
            )
        elif instruction in ("COPY", "ADD"):
            flags, sources, dest = split_copy_args(expand(arguments, stage.variables))
            if dest is None:
                continue
            source_stage = flags.get("from")
            if source_stage and source_stage not in named:
                continue
            available = named[source_stage].stamps if source_stage else context_stamps
            stage.stamps |= copy_stamps(sources, dest, flags, available, stage.workdir)
            if not source_stage:
                for source in (s for s in sources if s.endswith(".sh")):
                    target = image_path(dest, stage.workdir)
                    if dest.endswith("/") or len(sources) > 1:
                        target = posixpath.join(target, posixpath.basename(source))
                    stage.scripts[target] = source
        elif instruction == "RUN":
            command = expand(arguments, stage.variables)
            for path in removed_paths(command, stage.workdir):
                prefix = path.rstrip("/") + "/"
                stage.stamps = {
                    s for s in stage.stamps if s != path and not s.startswith(prefix)
                }
            if re.search(r"pip[0-9.]*\s+install[^&;|]*\s(\.|/\S+)(\s|$)", command):
                stage.installs_package = True
        elif instruction == "ENTRYPOINT":
            stage.entrypoint = parse_command(arguments)
            stage.cmd = None
        elif instruction == "CMD":
            stage.cmd = parse_command(arguments)
    code_dir = stamp_code_dir(connector_dir)
    packaged = code_dir if code_dir and code_dir != "src" else None
    if packaged and stage.installs_package and package_ships_stamp(connector_dir):
        stage.stamps.add(
            posixpath.join(SITE_PACKAGES, posixpath.basename(packaged), STAMP)
        )
    return stage, posixpath.basename(packaged) if packaged else None


def python_anchors(tokens, cwd, package):
    """(entry directory, sys.path[0]) of a python invocation, or None."""
    args = tokens[1:]
    for i, arg in enumerate(args):
        if arg == "-m" and i + 1 < len(args):
            module = args[i + 1].split(".")
            if package and module[0] == package:
                return posixpath.join(SITE_PACKAGES, *module), cwd
            return image_path("/".join(module), cwd), cwd
        if arg.startswith("-"):
            continue
        script_dir = posixpath.dirname(image_path(arg, cwd))
        return script_dir, script_dir
    return None


def shell_anchors(script, cwd, package, variables):
    """Follow ``cd`` and find the python invocation of a shell entry point."""
    for raw in script.splitlines():
        line = expand(raw.strip(), variables)
        if not line or line.startswith("#"):
            continue
        for segment in re.split(r"&&|;", line):
            try:
                tokens = shlex.split(segment)
            except ValueError:
                continue
            while tokens and tokens[0] in ("exec", "nohup", "env"):
                tokens = tokens[1:]
            if not tokens:
                continue
            if tokens[0] == "cd" and len(tokens) > 1:
                cwd = image_path(tokens[1], cwd)
            elif PYTHON_EXECUTABLE.match(tokens[0]):
                anchors = python_anchors(tokens, cwd, package)
                if anchors:
                    return anchors, cwd
    return None, cwd


def entry_anchors(connector_dir, stage, package):
    """Directories pycti reads, or None when the entry point is not understood."""
    command = [
        expand(part, stage.variables)
        for part in (stage.entrypoint or []) + (stage.cmd or [])
    ]
    cwd = stage.workdir
    if not command:
        return None
    executable = command[0]
    if SHELL_EXECUTABLE.match(executable) and "-c" in command[1:]:
        index = command.index("-c")
        anchors, cwd = shell_anchors(
            " ".join(command[index + 1 :]), cwd, package, stage.variables
        )
    elif PYTHON_EXECUTABLE.match(executable):
        anchors = python_anchors(command, cwd, package)
    else:
        if SHELL_EXECUTABLE.match(executable) and len(command) > 1:
            # `sh /entrypoint.sh`: the shell runs a script file
            executable = command[1]
        script_path = image_path(executable, cwd)
        context_script = stage.scripts.get(script_path)
        if context_script and (connector_dir / context_script).is_file():
            text = (connector_dir / context_script).read_text(encoding="utf-8")
            anchors, cwd = shell_anchors(text, cwd, package, stage.variables)
        else:
            # A console script installed by pip: its own directory is not a
            # connector directory, the working directory is.
            anchors = (posixpath.dirname(script_path), posixpath.dirname(script_path))
    if not anchors:
        return None
    entry, sys_path = anchors
    return {entry, sys_path, cwd}


def check_image(image, connector_dir, dockerfile, build_args=None):
    stage, package = analyse_dockerfile(connector_dir, dockerfile, build_args or {})
    anchors = entry_anchors(connector_dir, stage, package)
    if anchors is None:
        return Result(image, False, "entry point not understood (CMD / ENTRYPOINT)")
    readable = {directory for anchor in anchors for directory in ancestors(anchor)}
    found = sorted(s for s in stage.stamps if posixpath.dirname(s) in readable)
    if found:
        return Result(image, True, f"stamp at {found[0]}")
    rules = dockerignore_rules(connector_dir)
    ignored = [
        f"{stamp} (pattern '{rule}')"
        for stamp in written_stamps(connector_dir)
        if (rule := ignored_by(stamp, rules))
    ]
    if ignored:
        return Result(image, False, "excluded by .dockerignore: " + ", ".join(ignored))
    if not stage.stamps:
        return Result(image, False, "no COPY carries a stamp into the final image")
    return Result(
        image,
        False,
        f"stamp at {sorted(stage.stamps)[0]}, pycti reads {sorted(anchors)}",
    )


def check_connector(connector_dir, root, ubi9):
    """One result per image the pipeline builds for the connector."""
    name = connector_dir.relative_to(root).as_posix()
    results = [check_image(name, connector_dir, connector_dir / "Dockerfile")]
    if (connector_dir / "Dockerfile_fips").is_file():
        results.append(
            check_image(
                f"{name} (fips)", connector_dir, connector_dir / "Dockerfile_fips"
            )
        )
    if name in ubi9 and (root / UBI9_DOCKERFILE).is_file():
        top = name.split("/")[0]
        build_args = {
            "CONNECTOR_TYPE": top.upper().replace("-", "_"),
            **build_env(connector_dir),
        }
        results.append(
            check_image(
                f"{name} (ubi9)", connector_dir, root / UBI9_DOCKERFILE, build_args
            )
        )
    return results


def connector_dirs(root):
    """Every connector, and the templates new connectors start from."""
    for parent in (*CONNECTOR_TYPES, "templates"):
        parent_dir = root / parent
        if parent_dir.is_dir():
            for child in sorted(parent_dir.iterdir()):
                if (child / "Dockerfile").is_file():
                    yield child


def ubi9_connectors(root):
    path = root / UBI9_CONNECTORS
    if not path.is_file():
        return set()
    return set(json.loads(path.read_text(encoding="utf-8")))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "connectors", nargs="*", help="connector directories (default: all)"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--verbose", action="store_true", help="also list the covered images"
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if args.connectors:
        dirs = [
            (root / connector).resolve()
            for connector in args.connectors
            if (root / connector / "Dockerfile").is_file()
        ]
    else:
        dirs = list(connector_dirs(root))
    ubi9 = ubi9_connectors(root)
    results = [
        result
        for directory in dirs
        for result in check_connector(directory, root, ubi9)
    ]
    uncovered = [result for result in results if not result.covered]
    for result in results:
        if not result.covered:
            print(f"NOT COVERED {result.image}: {result.reason}")
        elif args.verbose:
            print(f"covered {result.image}: {result.reason}")
    covered = len(results) - len(uncovered)
    print(
        f"{covered} of {len(results)} connector images carry the stamp where pycti reads it."
    )
    return 1 if uncovered else 0


if __name__ == "__main__":
    sys.exit(main())
