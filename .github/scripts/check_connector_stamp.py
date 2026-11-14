#!/usr/bin/env python3
"""Check that every connector image carries its identity stamp where pycti reads it.

The shared image build (step "Write connector version stamp" of
.github/actions/build-connector-image) writes ``.connector_version.json``
(version and catalog slug) at the connector root and in its code directory
(``src/``, or the top-level package of a packaged connector). At registration,
pycti (``pycti/connector/opencti_connector_build.py``) looks for a file of that
exact name in the directory of the ``__main__`` file, of ``sys.path[0]`` and in
the working directory, each with up to four parent directories. The platform
then shows the connector with the logo and the title of its catalog entry.

For every image the pipeline builds (the connector ``Dockerfile``, its
``Dockerfile_fips``, and the shared ``Dockerfile_ubi9`` for the connectors of
``.github/ubi9-connectors.json`` with their ``.build.env``) and for the
connector templates, the script builds a model of the files of the final image
and of the command that starts it, then tells whether a stamp is where pycti
looks. The model covers exactly this:

* Build context: the files of the connector directory minus the
  ``.dockerignore`` rules (or a Dockerfile-specific ``<Dockerfile>.dockerignore``;
  last match wins, ``!`` exceptions), plus the stamps the build step writes.
* Instructions: FROM (stages), ARG / ENV, WORKDIR, COPY / ADD (``--from``
  read from the root of the stage, ``--parents``, ``--exclude``, wildcards,
  file and directory destinations; a ``--chmod`` that removes a read
  permission replaces the destination with a stamp that does not count;
  content the model does not know - an external image, a URL, an archive -
  takes the destination, or everything below a destination directory, out of
  the model), RUN, SHELL, VOLUME (a stamp below a volume does not count: a
  mount hides it), CMD / ENTRYPOINT (exec and shell forms).
* RUN commands and entry scripts, read as POSIX shell: quoted and escaped
  punctuation stays an argument; each command expands its variables with the
  values the preceding ones left (an unquoted expansion is split into words,
  nothing expands inside single quotes; a variable set inside a branch is no
  longer known). Commands joined by ``&&`` are followed as if each succeeds.
  An output redirection takes its target out of the model.
* Closed world: a command is accepted only when the model knows its effect on
  the files, otherwise the image is reported. Interpreted: ``cd``, ``rm``,
  ``unlink``, ``mv`` (sources and replaced destination), ``ln`` (literal and
  wildcard operands, a wildcard never matching a leading dot), ``find``
  (``-delete``, ``-exec rm`` and its operands; a grouped expression deletes
  everything below its roots), ``sh -c`` and shell scripts of the image,
  ``pip`` (``install <path>``, ``uninstall``, options writing a file),
  ``python -m venv`` (``--clear``), ``uv venv`` / ``uv pip``. Without effect
  on a connector file: commands that only read or create (``ls``, ``cat``,
  ``mkdir``, ``chown``, a ``chmod`` that keeps files readable, ...), system
  package managers (not with an option that moves their root), ``git clone``,
  ``python -m compileall``. Writing what they name: ``wget`` / ``curl``
  outputs. Reviewed: the programs of ``AUDITED_PROGRAMS`` and the build-time
  scripts of ``AUDITED_BUILD_SCRIPTS``, pinned by the digest of their text.
  Anything else - another program, python code at build time, a python
  process started after another one of the start command - is reported.
* Packaged connectors: the installed package carries the stamp only when the
  stamp reached the package directory before ``pip install``, setuptools
  discovery installs the package (``packages``, ``packages.find`` with its
  ``where`` / ``include`` / ``exclude`` / ``namespaces``) and its package data
  (``pyproject.toml`` or ``setup.cfg``, exclusions included) selects it.
* Start command: the python interpreter with its script, its ``-m`` module
  (looked up in the working directory, ``PYTHONPATH`` and the installed
  packages, as ``-I``, ``-P``, ``-E`` and ``-S`` allow) or ``-c``, started
  directly or by a shell script of the image, with the environment ``env``
  gives it. A deletion of a native site-packages path also applies to the
  installed packages of the model.

Anything outside the model is reported as "not supported" with the construct
that stopped the analysis, never assumed to be fine: heredocs, variables the
build does not define, a directory change or the start of python inside a
conditional or a loop of the entry script, an entry point that is not a file
of the model, a command outside the closed world above or acting on a path it
cannot resolve, packaging the script does not read (``setup.py``, ``package-dir``, ``MANIFEST.in``
exclusions, automatic discovery of a namespace package, build backends other
than setuptools).

Usage:
    python3 .github/scripts/check_connector_stamp.py
        Check every connector; exit 1 when an image cannot carry the stamp.
    python3 .github/scripts/check_connector_stamp.py external-import/mitre ...
        Check the given connector directories only.
"""

import argparse
import configparser
import fnmatch
import hashlib
import json
import os
import posixpath
import re
import shlex
import sys
import tomllib
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
# Directories whose files the result depends on: the workflow runs the check
# whenever one of their files changes.
WATCHED_DIRECTORIES = (*CONNECTOR_TYPES, "templates")
# pycti reads the anchor directory and its first four parents.
STAMP_PARENT_DEPTH = 4
# Abstract location of the installed packages: the real path depends on the
# Python version of the base image, and pycti only needs the package directory.
SITE_PACKAGES = "/<site-packages>"
# Official images set no WORKDIR: a stage built on them starts in "/".
ROOT_WORKDIR_IMAGE = re.compile(
    r"^(docker\.io/(library/)?)?(python|alpine|debian|ubuntu)([:@]|$)"
    r"|^registry\.access\.redhat\.com/ubi\d+/"
)
# Directories of every base image: a file copied to one of them without a
# trailing slash lands inside it.
BASE_DIRECTORIES = frozenset(
    {
        "/",
        "/bin",
        "/etc",
        "/home",
        "/opt",
        "/root",
        "/srv",
        "/tmp",
        "/usr",
        "/usr/bin",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/lib",
        "/usr/local/sbin",
        "/usr/sbin",
        "/var",
    }
)
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Dockerfile instructions the model reads (LABEL, EXPOSE, USER, MAINTAINER and
# STOPSIGNAL change neither the files nor the start command; the HEALTHCHECK
# command must leave the files alone).
KNOWN_INSTRUCTIONS = frozenset(
    {
        "FROM",
        "ARG",
        "ENV",
        "WORKDIR",
        "COPY",
        "ADD",
        "RUN",
        "SHELL",
        "VOLUME",
        "ENTRYPOINT",
        "CMD",
        "LABEL",
        "EXPOSE",
        "USER",
        "MAINTAINER",
        "STOPSIGNAL",
        "HEALTHCHECK",
    }
)
DEFAULT_SHELL = ["/bin/sh", "-c"]
PYTHON = re.compile(r"^python(3(\.\d+)?)?$")
PIP = re.compile(r"^pip(3(\.\d+)?)?$")
SHELLS = frozenset({"sh", "bash", "dash", "ash"})
VARIABLE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
GLOB_CHARS = re.compile(r"[*?\[]")
HEREDOC = re.compile(r"<<-?\s*['\"]?[A-Za-z_]")
TARBALL = re.compile(r"\.(tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz)$")
COMMAND_PREFIXES = frozenset({"exec", "command", "nohup", "time", "builtin"})
REDIRECTIONS = frozenset({">", ">>", "<", ">&", "<&", "&>", "&>>", ">|", "<>"})
# Longest first: shlex returns a run of punctuation such as ");" as one token.
OPERATORS = (
    "&>>",
    "&&",
    "||",
    ";;",
    ">>",
    "<<",
    ">&",
    "<&",
    "&>",
    ">|",
    "<>",
    ";",
    "&",
    "|",
    "(",
    ")",
    "<",
    ">",
)
SEPARATORS = frozenset({";", "&&", "||", "|", "&", ";;", "\n"})
OUTPUT_REDIRECTIONS = frozenset({">", ">>", ">|", "&>", "&>>"})
# Quoted or escaped shell punctuation is an argument, not an operator: it is
# carried through shlex as a private-use character and restored afterwards.
PUNCTUATION = "();<>|&"
PROTECT = {char: chr(0xE000 + n) for n, char in enumerate(PUNCTUATION)}
RESTORE = str.maketrans({v: k for k, v in PROTECT.items()})
# A variable reference is kept as a marker until its command runs, so that it is
# expanded with the variables the preceding commands left; an unquoted one is
# split into words, as the shell does.
VAR_UNQUOTED, VAR_QUOTED, VAR_END = "\ue020", "\ue021", "\ue022"
# A command substitution, whose output is not known.
VAR_SUBST = "\ue023"
VAR_MARKER = re.compile(f"([{VAR_UNQUOTED}{VAR_QUOTED}{VAR_SUBST}])(\\d+){VAR_END}")
# Commands that cannot delete, truncate, move or rewrite a file they name: they
# read it, create something new, or change its owner. A command the model
# neither interprets nor lists here is reported.
HARMLESS_COMMANDS = frozenset(
    {
        ":",
        "[",
        "[[",
        "addgroup",
        "adduser",
        "basename",
        "cat",
        "chgrp",
        "chown",
        "command",
        "date",
        "df",
        "dirname",
        "du",
        "echo",
        "false",
        "file",
        "grep",
        "groupadd",
        "head",
        "id",
        "ls",
        "mkdir",
        "pgrep",
        "printenv",
        "printf",
        "pwd",
        "readlink",
        "realpath",
        "set",
        "sleep",
        "stat",
        "tail",
        "test",
        "touch",
        "true",
        "type",
        "umask",
        "uname",
        "useradd",
        "wait",
        "wc",
        "which",
        "whoami",
    }
)
# Commands the shell runs itself, without a PATH lookup.
SHELL_BUILTINS = frozenset(
    {
        ".",
        ":",
        "[",
        "cd",
        "command",
        "echo",
        "eval",
        "exec",
        "exit",
        "export",
        "false",
        "popd",
        "printf",
        "pushd",
        "pwd",
        "read",
        "return",
        "set",
        "shift",
        "source",
        "test",
        "trap",
        "true",
        "type",
        "umask",
        "unset",
        "wait",
    }
)
# Python modules run with -m that only add files (venv is modelled: --clear).
HARMLESS_PYTHON_MODULES = frozenset({"compileall", "ensurepip"})
# System package managers write below their root (/usr, /etc, /var), never in a
# connector directory; the options that move that root are reported.
PACKAGE_MANAGERS = {
    "apk": frozenset({"--root", "-p"}),
    "apt": frozenset({"-o", "--option"}),
    "apt-get": frozenset({"-o", "--option"}),
    "dnf": frozenset({"--installroot"}),
    "dpkg": frozenset({"--root", "--instdir", "--admindir"}),
    "microdnf": frozenset({"--installroot"}),
    "rpm": frozenset({"--root", "--dbpath"}),
    "yum": frozenset({"--installroot"}),
}
# Programs of base images or packages whose effect was reviewed: they write no
# connector file.
AUDITED_PROGRAMS = {
    "playwright": "downloads browsers into the cache of the user",
    "unogenerator_start": "starts the LibreOffice listener of export-file-ods",
}
# Build-time scripts of the repository whose effect was reviewed, by the sha256
# of their text (line endings normalised): any change to one of them is reported
# until it is reviewed again and its new digest recorded here.
AUDITED_BUILD_SCRIPTS = {
    "62c482b06a4c57722abc457bc554f35aa66044a7143d2a7222a30e1833b89686": (
        "internal-import-file/import-file-stix/src/stixmarx_warmup.py: pre-generates ~/.stixmarx"
    ),
    "04401404514018e9493a809bad20505ed868eed6919d4b6adb952b42cea6c75a": (
        "external-import/matrix/build_and_install_libolm.sh: builds libolm in /tmp, installs it in /usr/local"
    ),
}
PIP_OPTIONS_WITH_VALUE = frozenset(
    {
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "--trusted-host",
        "--platform",
        "--python-version",
        "--implementation",
        "--abi",
        "--src",
        "--upgrade-strategy",
        "--progress-bar",
        "--log",
        "--proxy",
        "--retries",
        "--timeout",
        "--exists-action",
        "--cert",
        "--client-cert",
        "--cache-dir",
        "-C",
        "--config-settings",
        "--global-option",
        "--no-binary",
        "--only-binary",
        "--report",
    }
)
# Options that install somewhere else than the interpreter's site-packages.
PIP_RELOCATING_OPTIONS = frozenset(
    {"-t", "--target", "--prefix", "--root", "--user", "--home", "--src"}
)
# Options whose value is a file pip writes.
PIP_WRITE_OPTIONS = frozenset({"--report", "--log", "--log-file"})
PYTHON_OPTIONS_WITH_VALUE = frozenset({"-W", "-X", "--check-hash-based-pycs"})


class Unsupported(Exception):
    """A construct outside the model: the image is reported, never assumed covered."""


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


def self_and_parents(path):
    """``path`` and every directory above it, up to "/"."""
    found = [path]
    while path != "/":
        path = posixpath.dirname(path)
        found.append(path)
    return found


def image_path(path, cwd, what="path"):
    """Absolute image path of ``path``, relative to ``cwd``."""
    if "$" in path or "`" in path:
        raise Unsupported(
            f"{what} '{path}' uses a variable or a command the build does not define"
        )
    if path.startswith("/"):
        return posixpath.normpath(path)
    if cwd is None:
        raise Unsupported(
            f"{what} '{path}' is relative to an unknown working directory"
        )
    return posixpath.normpath(posixpath.join(cwd, path))


def stamp_code_dir(connector_dir):
    """Mirror of the STAMP_DIR computation of the build step."""
    packages = sorted(
        main.parent
        for main in connector_dir.glob("*/__main__.py")
        if main.parent.name != "src"
    )
    if len(packages) > 1:
        names = ", ".join(package.name for package in packages)
        raise Unsupported(
            f"several top-level packages with a __main__.py ({names}): "
            "the build step stamps only the first one it finds"
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
    """Translate a Docker path pattern (.dockerignore, COPY) into a regular expression."""
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
        elif char == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 1
        elif char == "[" and pattern.find("]", i + 1) != -1:
            end = pattern.find("]", i + 1)
            body = pattern[i + 1 : end]
            if body.startswith(("!", "^")):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end
        else:
            out.append(re.escape(char))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def dockerignore_rules(path):
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


def ignore_file(connector_dir, dockerfile):
    """The ignore file BuildKit applies: ``<Dockerfile>.dockerignore`` first."""
    specific = dockerfile.parent / f"{dockerfile.name}.dockerignore"
    return specific if specific.is_file() else connector_dir / ".dockerignore"


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
    """Substitute the known variables; unknown ones are left as written."""

    def substitute(match):
        name = match.group(1) or match.group(4)
        operator, word = match.group(2), match.group(3)
        known = name in variables
        current = variables.get(name)
        if operator in (":-", "-"):
            if known and (current or operator == "-"):
                return current
            return expand(word, variables)
        if operator in (":+", "+"):
            if not known:
                return match.group(0)
            return expand(word, variables) if (current or operator == "+") else ""
        return current if known else match.group(0)

    return VARIABLE.sub(substitute, value)


def assignments(arguments):
    """Key / value pairs of an ENV or ARG instruction (value None: no default)."""
    try:
        tokens = shlex.split(arguments)
    except ValueError as error:
        raise Unsupported(f"ENV / ARG not understood: {arguments}") from error
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
    directives = True
    for raw in text.splitlines():
        stripped = raw.strip()
        # Parser directives come first ("# syntax=...", "# escape=..."), until
        # the first line that is not one.
        directive = re.match(r"#\s*([a-zA-Z]+)\s*=", stripped) if directives else None
        if directive and directive.group(1).lower() == "escape":
            raise Unsupported("the escape parser directive")
        directives = bool(directive)
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
    """(argv, shell form) of a CMD / ENTRYPOINT / RUN / SHELL value."""
    value = value.strip()
    if value.startswith("["):
        try:
            parsed = json.loads(value)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            return [str(item) for item in parsed], False
    return value, True


def split_copy_args(arguments):
    """Flags (name -> list of values), sources and destination of a COPY / ADD."""
    flags = {}
    rest = arguments.strip()
    while rest.startswith("--"):
        token, _, rest = rest.partition(" ")
        name, _, value = token[2:].partition("=")
        flags.setdefault(name, []).append(value if value else True)
        rest = rest.strip()
    try:
        items = json.loads(rest) if rest.startswith("[") else shlex.split(rest)
    except ValueError as error:
        raise Unsupported(f"COPY / ADD not understood: {arguments}") from error
    if len(items) < 2:
        return flags, [], None
    return flags, [str(item) for item in items[:-1]], str(items[-1])


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
        value = value.strip()
        if value.startswith('"'):
            value = value[1:]
        if value.endswith('"'):
            value = value[:-1]
        values[key.strip()] = value
    return values


class BuildContext:
    """The files a build of the connector directory can copy."""

    def __init__(self, connector_dir, rules):
        self.root = connector_dir
        self.rules = rules
        self.files = {}
        for directory, subdirs, names in os.walk(connector_dir):
            subdirs[:] = sorted(d for d in subdirs if d != ".git")
            for name in sorted(names):
                rel = (Path(directory) / name).relative_to(connector_dir).as_posix()
                if not ignored_by(rel, rules):
                    self.files[rel] = ("context", rel)
        self.stamps = written_stamps(connector_dir)
        for rel in self.stamps:
            if not ignored_by(rel, rules):
                self.files[rel] = ("stamp", rel)
        self.dirs = {"."}
        for rel in self.files:
            parts = rel.split("/")[:-1]
            for n in range(len(parts)):
                self.dirs.add("/".join(parts[: n + 1]))

    def read(self, origin):
        if origin is None or origin[0] != "context":
            return None
        return (self.root / origin[1]).read_text(encoding="utf-8", errors="replace")

    def ignored_stamps(self):
        return [
            f"{stamp} (pattern '{rule}')"
            for stamp in self.stamps
            if (rule := ignored_by(stamp, self.rules))
        ]


@dataclass
class Stage:
    """Files and settings of a build stage."""

    workdir: str = "/"
    files: dict = field(default_factory=dict)
    dirs: set = field(default_factory=lambda: set(BASE_DIRECTORIES))
    variables: dict = field(default_factory=dict)
    env: dict = field(default_factory=dict)
    shell: list = field(default_factory=lambda: list(DEFAULT_SHELL))
    entrypoint: tuple = None
    cmd: tuple = None
    volumes: list = field(default_factory=list)
    # Paths a build command wrote with content the model does not know (a link,
    # a moved file, a redirection target).
    replaced: set = field(default_factory=set)

    def child(self):
        # ENV values are part of the image; ARG values end with their stage.
        return Stage(
            workdir=self.workdir,
            files=dict(self.files),
            dirs=set(self.dirs),
            variables=dict(self.env),
            env=dict(self.env),
            shell=list(self.shell),
            entrypoint=self.entrypoint,
            cmd=self.cmd,
            volumes=list(self.volumes),
            replaced=set(self.replaced),
        )

    def add_file(self, path, origin):
        self.files[path] = origin
        for parent in self_and_parents(posixpath.dirname(path)):
            self.dirs.add(parent)

    def is_dir(self, path):
        prefix = path.rstrip("/") + "/"
        return path in self.dirs or any(f.startswith(prefix) for f in self.files)


def shell_glob_match(pattern, path):
    """Shell pathname expansion of ``pattern`` matches ``path`` (both absolute)."""
    pattern_parts = pattern.strip("/").split("/")
    path_parts = path.strip("/").split("/")
    if pattern == "/" or path == "/":
        return pattern == path
    if len(pattern_parts) != len(path_parts):
        return False
    for wanted, name in zip(pattern_parts, path_parts):
        if GLOB_CHARS.search(wanted):
            if name.startswith(".") and not wanted.startswith("."):
                return False
            if not fnmatch.fnmatchcase(name, wanted):
                return False
        elif wanted != name:
            return False
    return True


# Where pip installs in the base images; the model keeps installed packages in SITE_PACKAGES.
NATIVE_SITE_PACKAGES = re.compile(
    r"^(?:/usr(?:/local)?|/opt/[^/]+|/[^/]*venv[^/]*)/lib(?:64)?/python3(?:\.\d+)?"
    r"/(?:site|dist)-packages(?=/|$)"
)
NATIVE_SITE_ROOTS = ("/usr/local/lib/python3", "/usr/lib/python3", "/usr/lib64/python3")


def modelled_targets(target):
    """``target`` and, when it is a native path of the installed packages, the
    place where the model keeps them."""
    match = NATIVE_SITE_PACKAGES.match(target)
    if match:
        return [target, SITE_PACKAGES + target[match.end() :]]
    literal = (
        GLOB_CHARS.split(target, maxsplit=1)[0] if GLOB_CHARS.search(target) else None
    )
    above_site = any(
        root.startswith(target.rstrip("/") + "/") or root == target
        for root in NATIVE_SITE_ROOTS
    )
    if (
        above_site
        or "-packages" in target
        or (
            literal is not None
            and any(
                root.startswith(literal) or literal.startswith(root)
                for root in NATIVE_SITE_ROOTS
            )
        )
    ):
        # A parent of the installed packages, or a pattern that may reach them.
        return [target, SITE_PACKAGES]
    return [target]


def remove_files(files, target):
    """Delete ``target`` (absolute, wildcards allowed) and everything below it."""
    for modelled in modelled_targets(target):
        if GLOB_CHARS.search(modelled):

            def matches(candidate, pattern=modelled):
                return shell_glob_match(pattern, candidate)

        else:

            def matches(candidate, pattern=modelled):
                return candidate == pattern

        for path in list(files):
            if any(matches(candidate) for candidate in self_and_parents(path)):
                del files[path]


class PackagingConfig:
    """What setuptools installs from a source directory."""

    def __init__(self, texts):
        self.package_data = {}
        self.exclude_package_data = {}
        self.package_roots = ["."]
        self.packages = None
        self.include = []
        self.exclude = []
        # None: automatic discovery, whose namespace handling is not modelled.
        self.namespaces = None
        self.unsupported = None
        pyproject = texts.get("pyproject.toml")
        if pyproject is not None:
            self._read_pyproject(pyproject)
        setup_cfg = texts.get("setup.cfg")
        if setup_cfg is not None:
            self._read_setup_cfg(setup_cfg)
        if texts.get("setup.py") is not None:
            # setup() can override discovery, package data and directories.
            self.unsupported = self.unsupported or "packaging declared in setup.py"
        manifest = texts.get("MANIFEST.in")
        if manifest is not None and re.search(
            r"^\s*(exclude|recursive-exclude|global-exclude|prune)\b", manifest, re.M
        ):
            self.unsupported = self.unsupported or "exclusions of MANIFEST.in"

    def _read_pyproject(self, text):
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise Unsupported(f"pyproject.toml not readable: {error}") from error
        backend = data.get("build-system", {}).get("build-backend", "setuptools")
        if not backend.startswith("setuptools"):
            self.unsupported = f"package data of the build backend {backend}"
        tool = data.get("tool", {}).get("setuptools", {})
        for key in ("package-data", "package_data"):
            for package, patterns in tool.get(key, {}).items():
                self.package_data.setdefault(package, []).extend(patterns)
        for key in ("exclude-package-data", "exclude_package_data"):
            for package, patterns in tool.get(key, {}).items():
                self.exclude_package_data.setdefault(package, []).extend(patterns)
        packages = tool.get("packages")
        if isinstance(packages, list):
            self.packages = list(packages)
        elif isinstance(packages, dict) and "find" in packages:
            find = packages["find"]
            self.package_roots = [
                posixpath.normpath(root) for root in find.get("where", ["."])
            ]
            self.include = list(find.get("include", []))
            self.exclude = list(find.get("exclude", []))
            self.namespaces = bool(find.get("namespaces", True))
        if tool.get("package-dir") or tool.get("package_dir"):
            self.unsupported = self.unsupported or "package-dir of setuptools"

    def _read_setup_cfg(self, text):
        parser = configparser.ConfigParser(interpolation=None)
        # Package names are case-sensitive.
        parser.optionxform = str
        try:
            parser.read_string(text)
        except configparser.Error as error:
            raise Unsupported(f"setup.cfg not readable: {error}") from error

        def values(raw):
            return [v.strip() for v in re.split(r"[,\n]", raw) if v.strip()]

        if parser.has_section("options.package_data"):
            for package, raw in parser.items("options.package_data"):
                self.package_data.setdefault(package, []).extend(values(raw))
        if parser.has_section("options.exclude_package_data"):
            for package, raw in parser.items("options.exclude_package_data"):
                self.exclude_package_data.setdefault(package, []).extend(values(raw))
        if parser.has_option("options", "packages"):
            raw = parser.get("options", "packages").strip()
            if raw.startswith(("find:", "find_namespace:")):
                self.namespaces = raw.startswith("find_namespace:")
                if parser.has_option("options.packages.find", "where"):
                    self.package_roots = [
                        posixpath.normpath(root)
                        for root in values(parser.get("options.packages.find", "where"))
                    ]
                for option, target in (
                    ("include", self.include),
                    ("exclude", self.exclude),
                ):
                    if parser.has_option("options.packages.find", option):
                        target.extend(
                            values(parser.get("options.packages.find", option))
                        )
            elif raw:
                self.packages = values(raw)
        if parser.has_option("options", "package_dir"):
            self.unsupported = self.unsupported or "package_dir of setuptools"

    def installs(self, package, has_init):
        if self.packages is not None:
            return package in self.packages
        if not has_init:
            # A directory without __init__.py is only a namespace package.
            if self.namespaces is None:
                raise Unsupported(
                    f"automatic discovery of {package}, a directory without __init__.py"
                )
            if not self.namespaces:
                return False
        if self.include and not any(
            fnmatch.fnmatchcase(package, p) for p in self.include
        ):
            return False
        return not any(fnmatch.fnmatchcase(package, p) for p in self.exclude)

    def ships(self, package, filename):
        """The package data of ``package`` selects ``filename`` (at the package root)."""
        if self.unsupported:
            raise Unsupported(self.unsupported)

        def selected(declarations):
            patterns = [
                *declarations.get(package, []),
                *declarations.get("*", []),
                *declarations.get("", []),
            ]
            return any(package_data_matches(p, filename) for p in patterns)

        return selected(self.package_data) and not selected(self.exclude_package_data)


def package_data_matches(pattern, filename):
    """setuptools glob of a package data pattern, for a file at the package root."""
    pattern = pattern.strip()
    while pattern.startswith("**/"):
        pattern = pattern[3:]
    if "/" in pattern:
        return False
    # glob never lets a wildcard match the leading dot of a hidden file.
    if filename.startswith(".") and not pattern.startswith("."):
        return False
    return fnmatch.fnmatchcase(filename, pattern)


CHMOD_OPTIONS = frozenset(
    {
        "-R",
        "-v",
        "-c",
        "-f",
        "--recursive",
        "--verbose",
        "--changes",
        "--silent",
        "--quiet",
        "--preserve-root",
        "--no-preserve-root",
    }
)


def harmless_mode(args, search=False):
    """A chmod that only adds permissions, or sets a mode everyone can read (and,
    for a directory, search)."""
    modes = [a for a in args if a not in CHMOD_OPTIONS]
    if not modes:
        return True
    mode = modes[0]
    if re.fullmatch(r"[0-7]{3,4}", mode):
        needed = 5 if search else 4
        return all(int(digit) & needed == needed for digit in mode[-3:])
    return all(
        re.fullmatch(r"[ugoa]*\+[rwxXst]+", clause) for clause in mode.split(",")
    )


def target_options(args):
    """``mv`` / ``ln`` arguments: (target directory, whether -T is given, the
    arguments left once these options and their values are taken out)."""
    target = None
    no_target = False
    rest = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            rest.extend(args[i:])
            break
        if arg.startswith("--target-directory"):
            _, equals, value = arg.partition("=")
            if not equals:
                i += 1
                value = args[i] if i < len(args) else None
            target = value
        elif arg == "--suffix":
            i += 1
        elif arg == "--no-target-directory":
            no_target = True
        elif re.fullmatch(r"-[a-zA-Z].*", arg):
            # Short options in a cluster; -t and -S take the rest, or the next word.
            for position, letter in enumerate(arg[1:], 2):
                if letter == "T":
                    no_target = True
                elif letter in "tS":
                    value = arg[position:]
                    if not value:
                        i += 1
                        value = args[i] if i < len(args) else None
                    if letter == "t":
                        target = value
                    break
        else:
            rest.append(arg)
        i += 1
    return target, no_target, rest


def matching_parenthesis(line, opening):
    """Index of the ")" closing the "(" at ``opening``, quotes and escapes skipped."""
    depth = 0
    quote = None
    i = opening
    while i < len(line):
        char = line[i]
        if quote:
            if char == "\\" and quote == '"':
                i += 1
            elif char == quote:
                quote = None
        elif char == "\\":
            i += 1
        elif char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def script_digest(text):
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def audited(text):
    return script_digest(text) in AUDITED_BUILD_SCRIPTS


def python_module(args):
    """The module of ``python -m``, or None."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-" or not arg.startswith("-"):
            return None
        if arg.startswith("--"):
            i += 2 if arg in PYTHON_OPTIONS_WITH_VALUE else 1
            continue
        cluster = arg[1:]
        for position, letter in enumerate(cluster):
            rest = cluster[position + 1 :]
            if letter == "c":
                return None
            if letter == "m":
                return rest or (args[i + 1] if i + 1 < len(args) else None)
            if letter in "WX":
                if not rest:
                    i += 1
                break
        i += 1
    return None


def python_script(args):
    """The script of ``python [options] script``, or None (-m, -c, stdin)."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-":
            return None
        if not arg.startswith("-"):
            return arg
        if arg.startswith("--"):
            i += 2 if arg in PYTHON_OPTIONS_WITH_VALUE else 1
            continue
        cluster = arg[1:]
        if "c" in cluster or "m" in cluster:
            return None
        i += 2 if cluster[-1:] in ("W", "X") and len(cluster) == 1 else 1
    return None


def download_outputs(program, args, cwd):
    """Files ``wget`` or ``curl`` write; a response body otherwise goes to stdout."""
    outputs, urls = [], []
    directory = None
    remote_name = program == "wget"
    options = {
        "wget": {
            "-O": "file",
            "--output-document": "file",
            "-o": "file",
            "--output-file": "file",
            "-a": "file",
            "--append-output": "file",
            "-P": "dir",
            "--directory-prefix": "dir",
        },
        "curl": {
            "-o": "file",
            "--output": "file",
            "-D": "file",
            "--dump-header": "file",
            "-c": "file",
            "--cookie-jar": "file",
            "--trace": "file",
            "--trace-ascii": "file",
            "--stderr": "file",
            "--output-dir": "dir",
        },
    }[program]
    i = 0
    while i < len(args):
        arg = args[i]
        option, sep, attached = arg.partition("=")
        if (
            not sep
            and not option.startswith("--")
            and option[:2] in options
            and len(option) > 2
        ):
            option, attached, sep = option[:2], option[2:], "attached"
        kind = options.get(option)
        if kind:
            value = attached if sep else (args[i + 1] if i + 1 < len(args) else None)
            i += 1 if sep else 2
            if kind == "dir":
                directory = value
            elif value:
                outputs.append(value)
                if program == "wget" and option in ("-O", "--output-document"):
                    remote_name = False
            continue
        if program == "curl" and arg in ("-O", "--remote-name", "--remote-name-all"):
            remote_name = True
        elif "://" in arg:
            urls.append(arg)
        i += 1
    if remote_name:
        for url in urls:
            name = (
                posixpath.basename(url.split("://", 1)[1].split("?")[0]) or "index.html"
            )
            outputs.append(posixpath.join(directory or ".", name))
    return [output for output in outputs if output != "-"]


def env_prefix(words, assigned, unset):
    """``env [-u NAME] [NAME=value] command``: the environment of the command."""
    assigned = dict(assigned)
    unset = set(unset)
    while words and (ASSIGNMENT.match(words[0]) or words[0].startswith("-")):
        option = words[0]
        if option in ("-C", "--chdir") or option.startswith("--chdir="):
            raise Unsupported("env --chdir")
        if option in ("-i", "--ignore-environment", "-"):
            raise Unsupported("env -i: the environment of the command is not modelled")
        if ASSIGNMENT.match(option):
            key, _, value = option.partition("=")
            assigned[key] = value
            unset.discard(key)
            words = words[1:]
        elif option in ("-u", "--unset"):
            if len(words) > 1:
                unset.add(words[1])
                assigned.pop(words[1], None)
            words = words[2:]
        elif option.startswith("--unset="):
            name = option.partition("=")[2]
            unset.add(name)
            assigned.pop(name, None)
            words = words[1:]
        else:
            words = words[1:]
    return words, assigned, unset


def interpreter_of(text):
    """Program named by the interpreter line of a script, or an empty string."""
    if not text or not text.startswith("#!"):
        return ""
    interpreter = text.splitlines()[0][2:].split()
    if interpreter and posixpath.basename(interpreter[0]) == "env":
        interpreter = [a for a in interpreter[1:] if not a.startswith("-")]
    return posixpath.basename(interpreter[0]) if interpreter else ""


def shell_script(args, cwd, files, model):
    """What a shell started with ``args`` runs: its ``-c`` string or a script
    file of the image model; None when it reads its standard input."""
    i = 0
    while i < len(args) and args[i].startswith(("-", "+")):
        option = args[i]
        if not option.startswith("--") and "c" in option[1:]:
            if i + 1 >= len(args):
                raise Unsupported("'sh -c' without a command")
            return args[i + 1]
        i += 2 if option in ("-o", "+o") else 1
    if i >= len(args):
        return None
    path = image_path(args[i], cwd, "shell script")
    text = model.context.read(files.get(path))
    if text is None:
        raise Unsupported(f"shell script {path} is not a file of the image model")
    return text


class Shell:
    """POSIX shell commands of a RUN instruction or of an entry script.

    ``start`` is False for a RUN (its effects are applied to the stage) and True
    for the start of the container: every python process the script starts is
    collected with the files of the image at that moment, until ``exec`` hands
    the container over or the script exits.
    """

    def __init__(self, model, stage, files, cwd, variables, start, nesting=0):
        self.model = model
        self.stage = stage
        self.files = files
        self.cwd = cwd
        self.variables = variables
        self.start = start
        self.nesting = nesting
        self.stack = []
        self.processes = []
        self.ended = False
        # Variable references of the script, in the order the markers number them.
        self.references = []
        # Commands of the command substitutions, run once before their command.
        self.substitutions = []

    def run(self, script):
        if self.nesting > 8:
            raise Unsupported("shell scripts nested too deeply")
        for line in self._lines(script):
            if HEREDOC.search(line):
                raise Unsupported("a here-document in a shell script")
            self._statements(self._tokens(line) + ["\n"])
            if self.ended:
                break
        return self.processes

    def _expand(self, word, split=True):
        """Words of ``word`` once its variables are expanded with the current
        values; an unquoted expansion is split on blanks."""
        unquoted = False

        def substitute(match):
            nonlocal unquoted
            if match.group(1) == VAR_SUBST:
                # Unknown output: a "$" stays, so a path built from it is reported.
                return "$(...)"
            unquoted = unquoted or match.group(1) == VAR_UNQUOTED
            return expand(self.references[int(match.group(2))], self.variables)

        value = VAR_MARKER.sub(substitute, word)
        return value.split() if split and unquoted else [value]

    def _nested(self, files, cwd, variables, start, conditional):
        """A shell run from this one; in a start script it adds its processes here."""
        nested = Shell(
            self.model,
            self.stage,
            files,
            cwd,
            variables,
            start,
            self.nesting + 1,
        )
        nested.stack = list(self.stack) + (["("] if conditional else [])
        nested.processes = self.processes
        return nested

    def _launch(self, words, env, conditional):
        if conditional:
            raise Unsupported(
                "the connector started inside a conditional or a loop of the entry script"
            )
        if self.model.foreign_effects:
            raise Unsupported(
                "a python process starts after another one whose effects on the files are not modelled"
            )
        self.processes.extend(
            self.model.launch(words, self.cwd, env, self.files, self.nesting + 1)
        )

    @staticmethod
    def _lines(script):
        lines = []
        current = ""
        for raw in script.splitlines():
            if raw.endswith("\\"):
                current += raw[:-1]
                continue
            lines.append(current + raw)
            current = ""
        if current:
            lines.append(current)
        return lines

    def _protect(self, line):
        """The line with quoted or escaped punctuation as private-use characters
        and variable references as markers (none inside single quotes)."""
        out = []
        quote = None
        i = 0
        while i < len(line):
            char = line[i]
            if (
                quote is None
                and char == "#"
                and (i == 0 or line[i - 1].isspace() or line[i - 1] in ";&|()")
            ):
                # A comment, up to the end of the line.
                end = line.find("\n", i)
                i = len(line) if end < 0 else end
                continue
            if quote != "'" and line.startswith("$(", i):
                # Command substitution: its commands run before the command that
                # uses it; its output is not known.
                end = matching_parenthesis(line, i + 1)
                if end is None:
                    raise Unsupported("an unterminated command substitution")
                inner = line[i + 2 : end]
                arithmetic = inner.startswith("(") and inner.endswith(")")
                out.append(f"{VAR_SUBST}{len(self.substitutions)}{VAR_END}")
                self.substitutions.append(None if arithmetic else inner)
                i = end + 1
                continue
            if quote != "'" and char == "`":
                raise Unsupported("a backquoted command substitution")
            if quote is None and char in "<>" and line.startswith("(", i + 1):
                raise Unsupported("a process substitution")
            reference = (
                VARIABLE.match(line, i) if char == "$" and quote != "'" else None
            )
            if reference:
                kind = VAR_QUOTED if quote == '"' else VAR_UNQUOTED
                out.append(f"{kind}{len(self.references)}{VAR_END}")
                self.references.append(reference.group(0))
                i = reference.end()
                continue
            if quote:
                if char == quote:
                    quote = None
                    out.append(char)
                elif quote == '"' and char == "\\" and i + 1 < len(line):
                    out.append(char + PROTECT.get(line[i + 1], line[i + 1]))
                    i += 1
                else:
                    out.append(PROTECT.get(char, char))
            elif char in ("'", '"'):
                quote = char
                out.append(char)
            elif char == "\\" and i + 1 < len(line):
                following = line[i + 1]
                out.append(
                    PROTECT[following] if following in PROTECT else char + following
                )
                i += 1
            else:
                out.append(char)
            i += 1
        return "".join(out)

    def _tokens(self, line):
        lexer = shlex.shlex(self._protect(line), posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
        except ValueError as error:
            raise Unsupported(
                f"shell line not understood: {line.strip()[:80]}"
            ) from error
        split = []
        for token in tokens:
            if token and all(char in "();<>|&" for char in token):
                while token:
                    operator = next(o for o in OPERATORS if token.startswith(o))
                    split.append(operator)
                    token = token[len(operator) :]
            else:
                split.append(token)
        return split

    def _in_case(self):
        return bool(self.stack) and self.stack[-1] == "case"

    def _statements(self, tokens):
        """Split shell tokens into simple commands. Operators are recognised on
        the raw tokens; quoted or escaped punctuation reaches the commands as
        arguments."""
        words = []
        writes = []
        before = None
        skip = False
        skip_name = False
        redirect = None
        for token in tokens:
            if redirect is not None and token not in SEPARATORS:
                target = token.translate(RESTORE)
                if redirect in OUTPUT_REDIRECTIONS or (
                    redirect == ">&" and not target.isdigit() and target != "-"
                ):
                    writes.append(target)
                redirect = None
                continue
            redirect = None
            if token in SEPARATORS:
                if (words or writes) and not skip:
                    self._command(words, writes, before, token)
                words, writes, skip = [], [], False
                before = token if token != "\n" else None
                if self.ended:
                    return
                continue
            if skip:
                if skip == "for":
                    # The loop variable takes values the model does not follow.
                    self.variables.pop(token, None)
                    skip = True
                self._substitute([token], True)
                continue
            if skip_name:
                skip_name = False
                continue
            if token == "<<":
                raise Unsupported("a here-document in a shell script")
            if token in REDIRECTIONS:
                if words and words[-1].isdigit():
                    # 2>file: the file descriptor is not an argument.
                    words.pop()
                redirect = token
                continue
            if token in ("(", ")") and not self._in_case():
                if words or writes:
                    self._command(words, writes, before, token)
                    words, writes = [], []
                if token == "(":
                    self.stack.append("(")
                elif self.stack:
                    self.stack.pop()
                continue
            if token in ("(", ")"):
                continue
            if not words:
                if token in ("if", "while", "until", "{"):
                    self.stack.append(token)
                    continue
                if token in ("select", "case"):
                    # Its arms run or not depending on a value the model does not follow.
                    raise Unsupported(f"'{token}' in a shell script")
                if token == "for":
                    self.stack.append(token)
                    skip = "for"
                    continue
                if token in ("fi", "done", "esac", "}"):
                    if self.stack:
                        self.stack.pop()
                    continue
                if token in ("then", "do", "else", "elif", "!", "in"):
                    continue
                if token == "function":
                    skip_name = True
                    continue
            words.append(token.translate(RESTORE))
        if (words or writes) and not skip:
            self._command(words, writes, before, None)

    def _substitute(self, words, conditional):
        """Run the command substitutions of ``words``: their commands run before
        the command that uses their output."""
        for word in words:
            for match in VAR_MARKER.finditer(word):
                index = int(match.group(2))
                if match.group(1) == VAR_SUBST and self.substitutions[index]:
                    script, self.substitutions[index] = self.substitutions[index], None
                    self._nested(
                        self.files,
                        self.cwd,
                        dict(self.variables),
                        self.start,
                        conditional,
                    ).run(script)

    def _command(self, words, writes, before, after):
        conditional = bool(self.stack) or before == "||"
        self._substitute((*words, *writes), conditional)
        for target in writes:
            # Truncated or rewritten: the file no longer holds what the model knows.
            [value] = self._expand(target, split=False)
            path = image_path(self._tilde(value), self.cwd, "redirection target")
            remove_files(self.files, path)
            self.stage.replaced.add(path)
        assigned = {}
        while words and ASSIGNMENT.match(words[0]):
            key, _, value = words[0].partition("=")
            [assigned[key]] = self._expand(value, split=False)
            if all(ASSIGNMENT.match(w) for w in words):
                # Assignments alone apply one after the other; in a branch the model
                # does not follow, the variable is no longer known.
                if conditional:
                    self.variables.pop(key, None)
                else:
                    self.variables[key] = assigned[key]
            words = words[1:]
        if not words:
            return
        words = [part for word in words for part in self._expand(word)]
        if not words:
            return
        handed_over = False
        unset = set()
        while words:
            name = posixpath.basename(words[0])
            if name == "command" and words[1:2] and words[1] in ("-v", "-V"):
                # command -v: a lookup, nothing runs.
                return
            if name in COMMAND_PREFIXES:
                handed_over = handed_over or name == "exec"
                words = words[1:]
            elif name == "env":
                words, assigned, unset = env_prefix(words[1:], assigned, unset)
            elif name == "sudo":
                words = words[1:]
                while words and words[0].startswith("-"):
                    words = words[1:]
            else:
                break
        if not words:
            return
        in_pipeline = before == "|" or after == "|"
        name = posixpath.basename(words[0])
        args = words[1:]
        env = {
            key: value
            for key, value in {**self.variables, **assigned}.items()
            if key not in unset
        }
        if self.start and handed_over:
            # exec: the command replaces the script.
            self._launch(words, env, conditional)
            self.ended = True
            return
        if name == "export":
            for arg in args:
                key, sep, value = arg.partition("=")
                if not sep:
                    continue
                if conditional:
                    # A branch the model does not follow may or may not have run.
                    self.variables.pop(key, None)
                else:
                    self.variables[key] = value
            return
        if name == "unset":
            for arg in args:
                if not arg.startswith("-"):
                    self.variables.pop(arg, None)
            return
        if name not in SHELL_BUILTINS and self.model.shadow(
            words[0], env, self.files, self.stage
        ):
            # The file the build put on PATH under this name runs, not the
            # program the model knows by that name.
            if not self._executed_script(words, env, conditional):
                raise Unsupported(
                    f"'{name}' resolves on PATH to a file the build wrote, which the model does not know"
                )
            return
        if name == "cd":
            self._cd(args, conditional, in_pipeline)
        elif name in ("pushd", "popd"):
            self._unknown_directory(f"'{name}'")
        elif name == "eval":
            raise Unsupported("'eval': the commands it runs are not known")
        elif name in (".", "source"):
            if self.start:
                raise Unsupported(f"'{name}' in the entry script")
            self._source(name, args)
        elif name in ("rm", "unlink"):
            self._delete(self._operands(args))
        elif name == "mv":
            self._move(args)
        elif name == "ln":
            self._link(args)
        elif name == "find":
            self._find(args)
        elif name in SHELLS:
            self._nested_shell(args, conditional, env)
        elif PIP.match(name):
            self._pip(args, conditional)
        elif name == "uv":
            self._uv(args, conditional)
        elif PYTHON.match(name):
            self._python(words, env, conditional)
        elif name in ("exit", "return"):
            if not conditional and before != "&&":
                self.ended = True
        elif not self._executed_script(words, env, conditional):
            self._other_command(words)

    def _python(self, words, env, conditional):
        """python at build time or in a start script."""
        args = words[1:]
        module = python_module(args)
        if module == "pip":
            index = args.index("pip") if "pip" in args else len(args)
            self._pip(args[index + 1 :], conditional)
            return
        if self.start:
            self._launch(words, env, conditional)
            # What this process does to the files, for the ones started after it, is not known.
            self.model.foreign_effects = True
            return
        if module == "venv":
            self._venv(args)
            return
        if module in HARMLESS_PYTHON_MODULES:
            return
        script = python_script(args)
        if script is not None and module is None:
            path = image_path(script, self.cwd, "python script")
            self._audited_script(path)
            return
        raise Unsupported(
            "python code run at build time"
            + (f" (-m {module})" if module else " (-c)" if "-c" in args else "")
            + " has effects on the files the model does not know"
        )

    def _audited_script(self, path):
        text = self.model.context.read(self.files.get(path))
        if text is None:
            raise Unsupported(
                f"build-time script {path} is not a file of the image model"
            )
        digest = script_digest(text)
        if digest not in AUDITED_BUILD_SCRIPTS:
            raise Unsupported(
                f"build-time script {path} is not an audited script (sha256 {digest}):"
                " review what it does to the files and add it to AUDITED_BUILD_SCRIPTS"
            )

    def _venv(self, args):
        """``python -m venv [--clear] DIR``: --clear empties an existing DIR."""
        index = args.index("venv") + 1 if "venv" in args else len(args)
        options = args[index:]
        clear = "--clear" in options
        directories = []
        i = 0
        while i < len(options):
            if options[i] == "--prompt":
                i += 2
                continue
            if not options[i].startswith("-"):
                directories.append(options[i])
            i += 1
        for directory in directories:
            path = image_path(self._tilde(directory), self.cwd, "venv directory")
            if clear:
                remove_files(self.files, path)

    def _uv(self, args, conditional):
        if args[:1] == ["pip"]:
            self._pip(args[1:], conditional)
            return
        if args[:1] == ["venv"]:
            # uv venv replaces an existing environment directory.
            targets = [a for a in args[1:] if not a.startswith("-")]
            for target in targets or [".venv"]:
                self._forget(target)
            return
        raise Unsupported(f"'uv {' '.join(args[:1])}' is not modelled")

    def _other_command(self, words):
        """A command the model only accepts when it knows its effect on the files."""
        name = posixpath.basename(words[0])
        args = words[1:]
        if name == "printf" and "-v" in args[:-1]:
            # printf -v NAME sets a variable.
            self.variables.pop(args[args.index("-v") + 1], None)
            return
        if name in HARMLESS_COMMANDS or name in AUDITED_PROGRAMS:
            return
        if name == "chmod":
            recursive = any(a in ("-R", "--recursive") for a in args)
            operands = [a for a in args if a not in CHMOD_OPTIONS][1:]
            for operand in operands:
                path = image_path(self._tilde(operand), self.cwd, "chmod operand")
                # A directory also needs its search permission.
                if not harmless_mode(args, recursive or self._is_dir(path)):
                    # Files a non-root user may no longer read.
                    self._forget(operand)
            return
        if name in PACKAGE_MANAGERS:
            relocating = PACKAGE_MANAGERS[name]
            for arg in args:
                if arg.split("=", 1)[0] in relocating or any(
                    arg.startswith(option) and len(arg) > len(option)
                    for option in relocating
                    if not option.startswith("--")
                ):
                    raise Unsupported(f"'{name} {arg}' installs below another root")
            return
        if name in ("wget", "curl"):
            for output in download_outputs(name, args, self.cwd):
                self._forget(output)
            return
        if name == "git" and args[:1] == ["clone"]:
            # A clone creates a new directory (git refuses a non-empty one).
            return
        raise Unsupported(
            f"'{name}' is not a command the model knows the effects of on the image files"
        )

    def _forget(self, candidate):
        """``candidate`` (and everything below it) may have been rewritten."""
        if not candidate or candidate.startswith("-") or "\n" in candidate:
            return
        if "$" in candidate or "`" in candidate:
            raise Unsupported(
                f"a command acts on '{candidate}', which uses a variable or a command the build does not define"
            )
        if not candidate.startswith(("/", "~", "./", "../")) and "/" not in candidate:
            # A bare word is a file only when the model has it in the working directory.
            if self.cwd is None:
                if STAMP in candidate:
                    raise Unsupported(f"'{candidate}' in an unknown working directory")
                return
            path = posixpath.join(self.cwd, candidate)
            if path not in self.files and not any(
                f.startswith(path + "/") for f in self.files
            ):
                return
        path = image_path(self._tilde(candidate), self.cwd, "named path")
        if path != "/":
            remove_files(self.files, path)

    def _executed_script(self, words, env, conditional):
        """A shell script of the image run as a command: it runs here (its
        deletions count, and in a start script its python processes). A python
        script of the image is a python process of a start script. True when the
        command was one of these."""
        path = self.model.find_executable(words[0], self.cwd, env, self.files)
        text = self.model.context.read(self.files.get(path)) if path else None
        program = interpreter_of(text)
        if program in SHELLS:
            if not self.start and audited(text):
                return True
            nested = self._nested(
                self.files, self.cwd, dict(env), self.start, conditional
            )
            nested.run(text)
            return True
        if PYTHON.match(program):
            self._python([program, path, *words[1:]], env, conditional)
            return True
        return False

    def _source(self, name, args):
        """``. file`` runs the file in this shell: its ``cd`` and deletions count."""
        if name == "eval" or not args:
            self.cwd = None
            return
        path = image_path(args[0], self.cwd, "sourced file")
        text = self.model.context.read(self.files.get(path))
        if text is None:
            # A file the model does not know (a virtualenv activation script)
            # may change the working directory.
            self.cwd = None
            return
        nested = Shell(
            self.model,
            self.stage,
            self.files,
            self.cwd,
            self.variables,
            start=False,
            nesting=self.nesting + 1,
        )
        nested.stack = list(self.stack)
        nested.run(text)
        self.cwd = nested.cwd

    def _unknown_directory(self, why):
        if self.start:
            raise Unsupported(f"working directory changed by {why} in the entry script")
        self.cwd = None

    def _cd(self, args, conditional, in_pipeline):
        if in_pipeline:
            return
        targets = [a for a in args if a not in ("-L", "-P", "--")]
        if len(targets) != 1 or targets[0] == "-":
            self._unknown_directory("'cd' without a directory")
            return
        if conditional:
            self._unknown_directory("a conditional 'cd'")
            return
        target = self._tilde(targets[0])
        if self.variables.get("CDPATH") and not target.startswith(("/", ".")):
            self._unknown_directory("a relative 'cd' searched in CDPATH")
            return
        self.cwd = image_path(target, self.cwd, "'cd' target")

    def _tilde(self, value):
        if value == "~" or value.startswith("~/"):
            return self.variables.get("HOME", "/root") + value[1:]
        return value

    def _operands(self, args):
        operands = []
        options = True
        for arg in args:
            if options and arg == "--":
                options = False
            elif options and arg.startswith("-") and arg != "-":
                continue
            else:
                operands.append(arg)
        return operands

    def _delete(self, operands):
        for operand in operands:
            target = image_path(self._tilde(operand), self.cwd, "deleted path")
            remove_files(self.files, target)

    def _move(self, args):
        target_dir, no_target, rest = target_options(args)
        operands = self._operands(rest)
        sources = operands if target_dir else operands[:-1]
        if not sources:
            return
        destination = target_dir if target_dir else operands[-1]
        destination = image_path(self._tilde(destination), self.cwd, "mv destination")
        if target_dir or (
            not no_target and (len(sources) > 1 or self._is_dir(destination))
        ):
            # Into a directory: each source replaces the entry of its name there.
            for source in sources:
                name = posixpath.basename(source.rstrip("/"))
                remove_files(self.files, posixpath.join(destination, name))
                self.stage.replaced.add(posixpath.join(destination, name))
        else:
            remove_files(self.files, destination)
            self.stage.replaced.add(destination)
        # The moved files leave their place; where they land is not modelled.
        self._delete(sources)

    def _is_dir(self, path):
        prefix = path.rstrip("/") + "/"
        return path in self.stage.dirs or any(f.startswith(prefix) for f in self.files)

    def _link(self, args):
        """``ln``: the link replaces whatever the model had at its path."""
        target_dir, no_target, rest = target_options(args)
        operands = self._operands(rest)
        if not operands:
            return
        if target_dir:
            link = image_path(self._tilde(target_dir), self.cwd, "link directory")
            targets = operands
        else:
            link = image_path(self._tilde(operands[-1]), self.cwd, "link path")
            targets = operands[:-1] or [operands[-1]]
            remove_files(self.files, link)
            self.stage.replaced.add(link)
            if no_target:
                return
        for target in targets:
            # A link created inside an existing directory takes the target's name.
            name = posixpath.basename(target.rstrip("/"))
            remove_files(self.files, posixpath.join(link, name))
            self.stage.replaced.add(posixpath.join(link, name))

    def _find(self, args):
        roots = []
        while args and not args[0].startswith("-") and args[0] not in ("(", "!", ")"):
            roots.append(args[0])
            args = args[1:]
        roots = roots or ["."]
        deletes = "-delete" in args
        for index, arg in enumerate(args):
            if arg.startswith(("-fprint", "-fls")) and index + 1 < len(args):
                # find writes this file.
                self._forget(args[index + 1])
            if arg not in ("-exec", "-execdir", "-ok", "-okdir"):
                continue
            command = []
            for word in args[index + 1 :]:
                if word in (";", "+"):
                    break
                command.append(word)
            if not command:
                continue
            program = posixpath.basename(command[0])
            if program in SHELLS or program == "xargs":
                raise Unsupported("a shell or xargs started from find")
            explicit = [word for word in command[1:] if word != "{}"]
            if program in ("rm", "unlink", "mv"):
                # Operands other than the matched path are deleted as well.
                deletes = True
                self._delete(self._operands(explicit))
            elif program in HARMLESS_COMMANDS or (
                program == "chmod" and harmless_mode(explicit, True)
            ):
                continue
            else:
                raise Unsupported(
                    f"find -exec {program}: its effect on the matched files is not modelled"
                )
        if not deletes:
            return
        kind, name = None, None
        understood = True
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in (
                "-type",
                "-name",
                "-mindepth",
                "-maxdepth",
                "-fprint",
                "-fls",
            ) and i + 1 < len(args):
                if arg == "-type":
                    kind = args[i + 1]
                elif arg == "-name":
                    name = args[i + 1]
                i += 2
                continue
            if arg == "-delete":
                i += 1
                continue
            if arg in ("-exec", "-execdir", "-ok", "-okdir"):
                while i < len(args) and args[i] not in (";", "+"):
                    i += 1
                i += 1
                continue
            understood = False
            break
        for root in roots:
            base = image_path(self._tilde(root), self.cwd, "find root")
            if GLOB_CHARS.search(base):
                raise Unsupported(f"find root '{root}' with a wildcard")
            prefix = base.rstrip("/") + "/"
            for path in list(self.files):
                if not (path == base or path.startswith(prefix)):
                    continue
                if not understood or name is None:
                    del self.files[path]
                    continue
                # find -name follows fnmatch: a wildcard matches a leading dot.
                file_hit = kind in (None, "f") and fnmatch.fnmatchcase(
                    posixpath.basename(path), name
                )
                dirs = [
                    d
                    for d in self_and_parents(posixpath.dirname(path))
                    if d == base or d.startswith(prefix)
                ]
                dir_hit = kind in (None, "d") and any(
                    fnmatch.fnmatchcase(posixpath.basename(d), name) for d in dirs
                )
                if file_hit or dir_hit:
                    del self.files[path]

    def _nested_shell(self, args, conditional, env):
        script = shell_script(args, self.cwd, self.files, self.model)
        if script is None:
            raise Unsupported("a shell reading its commands from its standard input")
        if not self.start and audited(script):
            return
        self._nested(self.files, self.cwd, dict(env), self.start, conditional).run(
            script
        )

    def _pip(self, args, conditional):
        """pip: ``install <path>`` records the installed packages; an option that
        writes a file (--report, --log) or into a directory takes it out of the
        model; ``uninstall`` removes installed packages."""
        if not args:
            return
        command, args = args[0], args[1:]
        relocated = False
        editable = False
        targets = []
        i = 0
        while i < len(args):
            arg = args[i]
            option, sep, attached = arg.partition("=")
            value = attached if sep else (args[i + 1] if i + 1 < len(args) else None)
            if option in PIP_WRITE_OPTIONS or option in PIP_RELOCATING_OPTIONS:
                relocated = relocated or option in PIP_RELOCATING_OPTIONS
                if option == "--user":
                    i += 1
                    continue
                if value:
                    self._forget(value)
                i += 1 if sep else 2
                continue
            if option in ("-e", "--editable"):
                editable = True
            if option in PIP_OPTIONS_WITH_VALUE:
                i += 1 if sep else 2
                continue
            if arg.startswith("-"):
                i += 1
                continue
            targets.append(arg)
            i += 1
        if command == "uninstall":
            # Which files a distribution owns is not modelled: none of the installed packages is kept.
            remove_files(self.files, SITE_PACKAGES)
            return
        if command != "install" or self.start or editable or conditional:
            return
        for target in targets:
            path = re.sub(r"\[[^\]]*\]$", "", target)
            if path.startswith("file://"):
                path = path[len("file://") :]
            if "://" in path or not (path.startswith((".", "/")) or "/" in path):
                continue
            if relocated:
                raise Unsupported(
                    "pip install into another directory than site-packages"
                )
            self.model.install_package(
                self.files, image_path(path, self.cwd, "pip install path")
            )


class ImageModel:
    """Files of the final image built from ``dockerfile`` and its start command."""

    def __init__(self, connector_dir, dockerfile, build_args):
        self.connector_dir = connector_dir
        self.context = BuildContext(
            connector_dir, dockerignore_rules(ignore_file(connector_dir, dockerfile))
        )
        self.build_args = build_args
        # Set once a python process of the start command ran: what it did to the files is not known.
        self.foreign_effects = False
        self.global_args = {}
        self.stages = []
        self.named = {}
        stage = None
        for line in logical_lines(dockerfile.read_text(encoding="utf-8")):
            # Any blank separates the instruction from its arguments.
            instruction, _, arguments = re.sub(r"\s", " ", line, count=1).partition(" ")
            instruction = instruction.upper()
            arguments = arguments.strip()
            if instruction not in KNOWN_INSTRUCTIONS:
                # ONBUILD triggers, for example, run in another stage.
                raise Unsupported(f"the {instruction} instruction")
            if instruction in ("RUN", "COPY", "ADD") and HEREDOC.search(arguments):
                raise Unsupported(f"a here-document in {instruction}")
            if instruction == "FROM":
                stage = self._from(arguments)
            elif instruction == "ARG" and stage is None:
                for key, value in assignments(arguments).items():
                    self.global_args[key] = build_args.get(key, value)
            elif stage is None:
                continue
            elif instruction == "ARG":
                self._arg(stage, arguments)
            elif instruction == "ENV":
                # Docker expands every value of one ENV with the variables before it.
                before = dict(stage.variables)
                for key, value in assignments(arguments).items():
                    if value is not None:
                        value = expand(value, before)
                        stage.variables[key] = value
                        stage.env[key] = value
            elif instruction == "WORKDIR":
                stage.workdir = image_path(
                    expand(arguments, stage.variables), stage.workdir, "WORKDIR"
                )
                for parent in self_and_parents(stage.workdir):
                    stage.dirs.add(parent)
            elif instruction in ("COPY", "ADD"):
                self._copy(stage, instruction, expand(arguments, stage.variables))
            elif instruction == "RUN":
                self._run(stage, arguments)
            elif instruction == "SHELL":
                shell, shell_form = parse_command(arguments)
                if shell_form or not shell:
                    raise Unsupported("SHELL not in the JSON form")
                stage.shell = shell
            elif instruction == "VOLUME":
                paths, shell_form = parse_command(expand(arguments, stage.variables))
                for path in paths.split() if shell_form else paths:
                    stage.volumes.append(image_path(path, stage.workdir, "VOLUME"))
            elif instruction == "ENTRYPOINT":
                stage.entrypoint = parse_command(arguments)
                stage.cmd = None
            elif instruction == "CMD":
                stage.cmd = parse_command(arguments)
            elif instruction == "HEALTHCHECK":
                self._healthcheck(stage, arguments)
        if stage is None:
            raise Unsupported("no FROM instruction")
        self.final = stage

    def _healthcheck(self, stage, arguments):
        """The health check runs next to the connector: it must leave the files alone."""
        rest = arguments
        while rest.startswith("--"):
            rest = rest.partition(" ")[2].strip()
        if rest.upper() == "NONE":
            return
        if not rest.upper().startswith("CMD"):
            raise Unsupported("a HEALTHCHECK without CMD")
        command, shell_form = parse_command(rest[3:].strip())
        files = dict(stage.files)
        variables = {"PATH": DEFAULT_PATH, **stage.env}
        shell = Shell(self, stage, files, stage.workdir, variables, start=False)
        if shell_form:
            shell.run(command)
        else:
            shell._statements([*command, "\n"])
        if files != stage.files:
            raise Unsupported("the HEALTHCHECK command changes files of the image")

    def _from(self, arguments):
        tokens = [t for t in arguments.split() if not t.startswith("--")]
        if not tokens:
            raise Unsupported("FROM without an image")
        image = expand(tokens[0], self.global_args)
        source = self.named.get(image.lower())
        if source is not None:
            stage = source.child()
        else:
            stage = Stage()
            # Every base image sets PATH; ENV PATH=/x:$PATH extends it.
            stage.variables["PATH"] = DEFAULT_PATH
            stage.env["PATH"] = DEFAULT_PATH
            if not ROOT_WORKDIR_IMAGE.match(image):
                # The working directory of another base image is not known.
                stage.workdir = None
        self.stages.append(stage)
        self.named[str(len(self.stages) - 1)] = stage
        if len(tokens) >= 3 and tokens[-2].upper() == "AS":
            self.named[tokens[-1].lower()] = stage
        return stage

    def _arg(self, stage, arguments):
        before = dict(stage.variables)
        for key, value in assignments(arguments).items():
            if key in self.build_args:
                value = self.build_args[key]
            elif value is None:
                value = self.global_args.get(key)
            else:
                value = expand(value, before)
            if value is not None:
                stage.variables[key] = value

    def _copy(self, stage, instruction, arguments):
        flags, sources, dest = split_copy_args(arguments)
        if dest is None:
            return
        from_values = flags.get("from", [])
        excludes = [
            glob_regex(p) for p in flags.get("exclude", []) if isinstance(p, str)
        ]
        keep_parents = bool(flags.get("parents"))
        opaque = False
        if from_values:
            source_stage = self.named.get(str(from_values[-1]).lower())
            if source_stage is None:
                # An external image: none of the connector's files come from it,
                # but its files may replace ones of the model.
                entries, opaque = [], True
            else:
                entries = self._stage_entries(source_stage, sources)
        else:
            entries, opaque = self._context_entries(instruction, sources)
        dest_path = image_path(dest, stage.workdir, "COPY destination")
        many = len(sources) > 1 or any(GLOB_CHARS.search(s) for s in sources)
        dest_is_dir = dest.endswith("/") or dest in (".", "./") or many
        if opaque:
            # Content the model does not know (external image, URL, archive) may
            # replace the destination, or anything below a destination directory.
            remove_files(stage.files, dest_path)

        chmod = flags.get("chmod", [])
        unreadable = bool(chmod) and not harmless_mode([str(chmod[-1])])
        # Copied directories get the mode as well: it must keep them searchable.
        unsearchable = bool(chmod) and not harmless_mode([str(chmod[-1])], True)

        def excluded(relative, name):
            # Matched against the path in the source and in the context: never less than Docker excludes.
            return any(rx.match(name) or rx.match(relative) for rx in excludes)

        def place(target, origin, in_directory=False):
            if origin[0] == "stamp" and (unreadable or (in_directory and unsearchable)):
                # --chmod removes a read permission: the copy replaces the
                # destination with a stamp a non-root user cannot read.
                stage.files.pop(target, None)
            else:
                stage.add_file(target, origin)

        for kind, source, members in entries:
            if kind == "dir" or keep_parents:
                for relative, member_origin, member_name in members:
                    if excluded(relative, member_name):
                        continue
                    if keep_parents:
                        target = posixpath.join(dest_path, member_name)
                    else:
                        target = (
                            posixpath.join(dest_path, relative)
                            if relative
                            else dest_path
                        )
                    place(posixpath.normpath(target), member_origin, bool(relative))
                stage.dirs.add(dest_path)
                continue
            relative, member_origin, member_name = members[0]
            if excluded(relative, member_name):
                continue
            if dest_is_dir or stage.is_dir(dest_path):
                target = posixpath.join(dest_path, posixpath.basename(member_name))
            else:
                target = dest_path
            place(target, member_origin)

    def _context_entries(self, instruction, sources):
        """(kind, source, [(relative path, origin, context path)]) per copied
        source, and whether a source brings content the model does not know."""
        entries = []
        opaque = False
        for source in sources:
            if instruction == "ADD" and ("://" in source or source.startswith("git@")):
                opaque = True
                continue
            normalized = (
                posixpath.normpath(source.lstrip("/"))
                if source not in (".", "./", "/")
                else "."
            )
            if GLOB_CHARS.search(normalized):
                regex = glob_regex(normalized)
                matches = sorted(
                    rel
                    for rel in (*self.context.files, *self.context.dirs)
                    if regex.match(rel)
                )
            else:
                matches = (
                    [normalized]
                    if (
                        normalized in self.context.files
                        or normalized in self.context.dirs
                    )
                    else []
                )
            for match in matches:
                if instruction == "ADD" and TARBALL.search(match):
                    # A local archive is extracted: its content is not modelled.
                    opaque = True
                    continue
                if match in self.context.dirs and match not in self.context.files:
                    prefix = "" if match == "." else match + "/"
                    members = [
                        (rel[len(prefix) :], origin, rel)
                        for rel, origin in self.context.files.items()
                        if rel.startswith(prefix)
                    ]
                    entries.append(("dir", match, members))
                else:
                    entries.append(
                        (
                            "file",
                            match,
                            [
                                (
                                    posixpath.basename(match),
                                    self.context.files[match],
                                    match,
                                )
                            ],
                        )
                    )
        return entries, opaque

    @staticmethod
    def _stage_entries(source_stage, sources):
        entries = []
        for source in sources:
            # Docker reads COPY --from sources from the root of the stage, not its WORKDIR.
            path = image_path(source, "/", "COPY --from source")
            if GLOB_CHARS.search(path):
                # Docker wildcards: unlike the shell, "*" matches a leading dot.
                regex = glob_regex(path.lstrip("/"))
                matched = sorted(
                    {
                        candidate
                        for f in source_stage.files
                        for candidate in self_and_parents(f)
                        if candidate != "/" and regex.match(candidate.lstrip("/"))
                    }
                )
            else:
                matched = [path]
            for match in matched:
                if match in source_stage.files:
                    entries.append(
                        (
                            "file",
                            match,
                            [
                                (
                                    posixpath.basename(match),
                                    source_stage.files[match],
                                    match.lstrip("/"),
                                )
                            ],
                        )
                    )
                    continue
                prefix = "/" if match == "/" else match + "/"
                members = [
                    (f[len(prefix) :], origin, f.lstrip("/"))
                    for f, origin in source_stage.files.items()
                    if f.startswith(prefix)
                ]
                if members:
                    entries.append(("dir", match, members))
        return entries

    def _run(self, stage, arguments):
        while arguments.startswith("--"):
            _, _, arguments = arguments.partition(" ")
            arguments = arguments.strip()
        command, shell_form = parse_command(arguments)
        shell = Shell(
            self, stage, stage.files, stage.workdir, dict(stage.variables), start=False
        )
        if shell_form:
            if posixpath.basename(stage.shell[0]) not in SHELLS:
                raise Unsupported(f"RUN through the shell {stage.shell[0]}")
            shell.run(command)
        elif command:
            shell._statements([*command, "\n"])

    def install_package(self, files, install_dir):
        """``pip install <install_dir>``: the packages it puts in site-packages."""
        texts = {}
        for name in ("pyproject.toml", "setup.cfg", "setup.py", "MANIFEST.in"):
            origin = files.get(posixpath.join(install_dir, name))
            if origin is not None:
                texts[name] = self.context.read(origin) or ""
        if not texts:
            return
        config = None
        for root in ["."] + [r for r in self._roots(texts) if r != "."]:
            base = posixpath.normpath(posixpath.join(install_dir, root))
            names = sorted(
                {
                    f[len(base) + 1 :].split("/")[0]
                    for f in files
                    if f.startswith(base + "/")
                    and f.count("/") == base.count("/") + 2
                    and posixpath.basename(f) in ("__init__.py", "__main__.py")
                }
            )
            for package in names:
                config = config or PackagingConfig(texts)
                package_dir = f"{base}/{package}"
                has_init = f"{package_dir}/__init__.py" in files
                if root not in config.package_roots or not config.installs(
                    package, has_init
                ):
                    continue
                for path, origin in list(files.items()):
                    if path.startswith(package_dir + "/") and path.endswith(".py"):
                        files[SITE_PACKAGES + "/" + path[len(base) + 1 :]] = origin
                stamp = f"{package_dir}/{STAMP}"
                origin = files.get(stamp)
                if (
                    origin is not None
                    and origin[0] == "stamp"
                    and config.ships(package, STAMP)
                ):
                    files[f"{SITE_PACKAGES}/{package}/{STAMP}"] = origin

    @staticmethod
    def _roots(texts):
        try:
            return PackagingConfig(texts).package_roots
        except Unsupported:
            return ["."]

    def start(self):
        """Python processes of the start command: (directories pycti reads,
        files of the image when the process starts) for each."""
        stage = self.final
        self.foreign_effects = False
        argv = self._start_argv(stage)
        env = {"PATH": DEFAULT_PATH, **stage.env}
        return self.launch(argv, stage.workdir, env, dict(stage.files))

    @staticmethod
    def _start_argv(stage):
        def resolved(command):
            value, shell_form = command
            return [*stage.shell, value] if shell_form else list(value)

        if stage.entrypoint is not None:
            if stage.entrypoint[1]:
                # A shell-form ENTRYPOINT ignores CMD.
                return resolved(stage.entrypoint)
            argv = resolved(stage.entrypoint)
            if stage.cmd is not None:
                argv += resolved(stage.cmd)
        elif stage.cmd is not None:
            argv = resolved(stage.cmd)
        else:
            raise Unsupported("no CMD or ENTRYPOINT")
        if not argv:
            raise Unsupported("empty CMD / ENTRYPOINT")
        return argv

    def launch(self, argv, cwd, env, files, nesting=0):
        """Python processes ``argv`` starts, as in ``start``."""
        if nesting > 8:
            raise Unsupported("entry scripts nested too deeply")
        words = list(argv)
        while words and posixpath.basename(words[0]) in (*COMMAND_PREFIXES, "env"):
            name = posixpath.basename(words[0])
            words = words[1:]
            if name == "env":
                words, assigned, unset = env_prefix(words, {}, set())
                env = {
                    key: value
                    for key, value in {**env, **assigned}.items()
                    if key not in unset
                }
        if not words:
            raise Unsupported("empty start command")
        if "$" in words[0] or "`" in words[0]:
            raise Unsupported(
                f"start command '{words[0]}' uses a variable or a command the build does not define"
            )
        name = posixpath.basename(words[0])
        shadow = self.shadow(words[0], env, files, self.final)
        if shadow is None and PYTHON.match(name):
            return [(self.python_start(words, cwd, env, files), dict(files))]
        if shadow is None and name in SHELLS:
            script = shell_script(words[1:], cwd, files, self)
            if script is None:
                raise Unsupported("a shell started without a script")
            return self._script(files, cwd, env, nesting, script)
        path = shadow or self._executable(words[0], cwd, env, files)
        text = self._read(files, path)
        if not text.startswith("#!"):
            raise Unsupported(f"entry point {path} has no interpreter line")
        program = interpreter_of(text)
        if PYTHON.match(program):
            argv = [program, path, *words[1:]]
            return [(self.python_start(argv, cwd, env, files), dict(files))]
        if program in SHELLS:
            return self._script(files, cwd, env, nesting, text)
        raise Unsupported(
            f"entry point {path} runs {program or 'an unknown interpreter'}"
        )

    def _script(self, files, cwd, env, nesting, text):
        shell = Shell(self, self.final, files, cwd, dict(env), True, nesting)
        processes = shell.run(text)
        if not processes:
            raise Unsupported("the entry script never starts python")
        return processes

    def _read(self, files, path):
        text = self.context.read(files.get(path))
        if text is None:
            raise Unsupported(f"entry point {path} is not a file of the image model")
        return text

    @staticmethod
    def find_executable(command, cwd, env, files):
        """Image path of a command: a path, or a file of the model on PATH."""
        if "/" in command:
            if "$" in command or (cwd is None and not command.startswith("/")):
                return None
            return image_path(command, cwd)
        for directory in env.get("PATH", DEFAULT_PATH).split(":"):
            candidate = posixpath.join(directory, command)
            if directory.startswith("/") and candidate in files:
                return candidate
        return None

    @staticmethod
    def shadow(command, env, files, stage):
        """The path a bare command name resolves to on PATH when the build put a
        file there (a file of the model, or one a command replaced): that file
        runs, not the program the name stands for. None otherwise."""
        if "/" in command:
            return None
        for directory in env.get("PATH", DEFAULT_PATH).split(":"):
            candidate = posixpath.join(directory or ".", command)
            if not directory.startswith("/"):
                # A relative PATH entry depends on the working directory.
                if any(
                    posixpath.basename(p) == command for p in (*files, *stage.replaced)
                ):
                    raise Unsupported(f"'{command}' looked up in a relative PATH entry")
                continue
            if candidate in files or candidate in stage.replaced:
                return candidate
        return None

    def _executable(self, command, cwd, env, files):
        if "/" in command:
            return image_path(command, cwd, "entry point")
        path = self.find_executable(command, cwd, env, files)
        if path is None:
            raise Unsupported(
                f"entry point '{command}' is not a file of the image model"
            )
        return path

    def python_start(self, words, cwd, env, files):
        """Directories pycti reads for a python command line: the directory of
        the __main__ file and the working directory (sys.path[0] is one of them)."""
        args = words[1:]
        safe_path = False
        ignore_env = False
        no_site = False
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "-":
                return self._readable(None, cwd)
            if arg.startswith("--"):
                option = arg.split("=", 1)[0]
                i += 2 if option in PYTHON_OPTIONS_WITH_VALUE and "=" not in arg else 1
                continue
            if arg.startswith("-") and len(arg) > 1:
                cluster = arg[1:]
                for position, letter in enumerate(cluster):
                    # -P drops the working directory from sys.path; -I also
                    # ignores the environment (PYTHONPATH among it).
                    if letter in "IP":
                        safe_path = True
                    if letter in "EI":
                        ignore_env = True
                    if letter == "S":
                        # No site initialisation: the installed packages are not importable.
                        no_site = True
                    if letter in "cm":
                        rest = cluster[position + 1 :]
                        value = rest or (args[i + 1] if i + 1 < len(args) else None)
                        if value is None:
                            raise Unsupported(f"python -{letter} without a value")
                        if letter == "c":
                            return self._readable(None, cwd)
                        if not ignore_env and env.get("PYTHONSAFEPATH"):
                            safe_path = True
                        main_dir = self._module_dir(
                            value, cwd, env, files, safe_path, ignore_env, no_site
                        )
                        return self._readable(main_dir, cwd)
                    if letter in "WX":
                        if not cluster[position + 1 :]:
                            i += 1
                        break
                i += 1
                continue
            script = image_path(arg, cwd, "python script")
            if script not in files:
                # pycti resolves the script path: a file the model does not
                # know (a symbolic link, a file of the base image) may live
                # anywhere.
                raise Unsupported(
                    f"python script {script} is not a file of the image model"
                )
            return self._readable(posixpath.dirname(script), cwd)
        raise Unsupported("python started without a script or a module")

    @staticmethod
    def _readable(main_dir, cwd):
        anchors = [d for d in (main_dir, cwd) if d is not None]
        if not anchors:
            raise Unsupported("python started in an unknown working directory")
        return sorted(set(anchors))

    @staticmethod
    def _module_dir(module, cwd, env, files, safe_path, ignore_env, no_site=False):
        parts = module.split(".")
        if not all(part.isidentifier() for part in parts):
            raise Unsupported(f"python -m {module}")
        entries = [] if safe_path else [""]
        if not ignore_env and env.get("PYTHONPATH"):
            entries += env["PYTHONPATH"].split(":")
        bases = []
        for entry in entries:
            if not entry.startswith("/"):
                # The working directory, or a path relative to it.
                if cwd is None:
                    raise Unsupported(
                        f"python -m {module} in an unknown working directory"
                    )
                entry = image_path(entry or ".", cwd, "PYTHONPATH entry")
            bases.append(entry)
        if not no_site:
            bases.append(SITE_PACKAGES)
        for base in bases:
            path = posixpath.join(base, *parts)
            if f"{path}/__main__.py" in files:
                return path
            if f"{path}.py" in files:
                return posixpath.dirname(path)
        raise Unsupported(f"module {module} is not a file of the image model")


def check_image(image, connector_dir, dockerfile, build_args=None):
    try:
        model = ImageModel(connector_dir, dockerfile, build_args or {})
        processes = model.start()
    except Unsupported as error:
        return Result(image, False, f"not supported: {error}")
    # The start command may run several python processes: the connector is one
    # of them, so each must find the stamp.
    results = [coverage(image, model, anchors, files) for anchors, files in processes]
    missing = [result for result in results if not result.covered]
    if not missing:
        return results[0]
    if len(results) > 1:
        number = results.index(missing[0]) + 1
        missing[0].reason = (
            f"python process {number} of {len(results)}: {missing[0].reason}"
        )
    return missing[0]


def coverage(image, model, anchors, files):
    """Whether a python process reading ``anchors`` finds a stamp in ``files``."""
    readable = {directory for anchor in anchors for directory in ancestors(anchor)}
    stamps = sorted(
        path
        for path, origin in files.items()
        if origin[0] == "stamp" and posixpath.basename(path) == STAMP
    )
    found = [stamp for stamp in stamps if posixpath.dirname(stamp) in readable]

    def volume_of(stamp):
        return next(
            (v for v in model.final.volumes if stamp.startswith(v.rstrip("/") + "/")),
            None,
        )

    visible = [stamp for stamp in found if volume_of(stamp) is None]
    if visible:
        return Result(image, True, f"stamp at {visible[0]}")
    if found:
        return Result(
            image,
            False,
            f"stamp at {found[0]} is below VOLUME {volume_of(found[0])}: a mount at run time hides it",
        )
    if stamps:
        return Result(
            image, False, f"stamp at {stamps[0]}, pycti reads {sorted(anchors)}"
        )
    renamed = sorted(path for path, origin in files.items() if origin[0] == "stamp")
    if renamed:
        return Result(
            image, False, f"stamp copied as {renamed[0]}: pycti only reads {STAMP}"
        )
    ignored = model.context.ignored_stamps()
    if ignored:
        return Result(image, False, "excluded by .dockerignore: " + ", ".join(ignored))
    return Result(image, False, "no COPY carries a stamp into the final image")


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
