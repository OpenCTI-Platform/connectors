#!/usr/bin/env python3
"""Check that every connector image carries its identity stamp where pycti reads it.

The shared image build (step "Write connector version stamp" of
.github/actions/build-connector-image) writes ``.connector_version.json``
(version and catalog slug) at the connector root and in its code directory
(``src/``, or the top-level package of a packaged connector). At registration,
pycti (``pycti/connector/opencti_connector_build.py``) looks for a file of that
exact name in the directory of the ``__main__`` file, of ``sys.path[0]`` and in
the working directory, each with up to four parent directories; in each
directory it reads the connector manifest of a source checkout
(``__metadata__/connector_manifest.json``) first, and it keeps the first file
that gives a version, so the stamp must be the first such file it meets. The
platform then shows the connector with the logo and the title of its catalog
entry.

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
  longer known; an expansion that assigns one, ``${NAME:=word}`` or
  ``${NAME=word}``, is reported). Commands joined by ``&&`` are followed as if
  each succeeds. An output redirection takes its target out of the model.
* Closed world: a command is accepted only when the model knows its effect on
  the files, otherwise the image is reported. Interpreted: ``cd``, ``rm``,
  ``unlink``, ``mv`` (sources and replaced destination), ``ln`` (literal and
  wildcard operands, a wildcard never matching a leading dot), ``touch`` (a
  file it creates is empty, a content the model does not know), ``find``
  (``-delete``, ``-exec rm`` and its operands; a grouped expression deletes
  everything below its roots), ``sh -c`` and shell scripts of the image,
  ``pip`` (``install <path>``, ``uninstall``, options writing a file),
  ``python -m venv`` (``--clear``), ``uv venv`` / ``uv pip``. Without effect
  on a connector file: commands that only read or create (``ls``, ``cat``,
  ``mkdir``, ``chown``, a ``chmod`` that keeps files readable, ...), system
  package managers (not with an option that moves their root), ``git clone``,
  ``python -m compileall``. Writing what they name: ``wget`` / ``curl``
  outputs. Reviewed: the programs of ``AUDITED_PROGRAMS`` (only the
  subcommands of ``AUDITED_SUBCOMMANDS`` where it lists the program) and the
  build-time scripts of ``AUDITED_BUILD_SCRIPTS``, pinned by the digest of
  their text.
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
import tarfile
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

STAMP = ".connector_version.json"
# pycti reads, in each directory it walks, the manifest of a source checkout
# before the stamp, and takes the first one that gives a usable version.
MANIFEST = "__metadata__/connector_manifest.json"
IDENTITY_FILES = (MANIFEST, STAMP)
VERSION_SENTINELS = frozenset({"", "unknown", "none", "null", "undefined"})
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
# Base images whose configuration is known (read from their published image
# configuration): they start in "/" and declare no ENTRYPOINT, VOLUME or ONBUILD
# trigger. The final image must start from one of them. The onbuild variants of
# the python image run build triggers, and of the UBI images only ubi-minimal is
# documented for connectors.
KNOWN_BASE_IMAGE = re.compile(
    r"^(docker\.io/(library/)?)?(python|alpine|debian|ubuntu)(?![^@]*onbuild)([:@]|$)"
    r"|^(docker\.io/)?filigran/alpine-python-fips([:@]|$)"
    r"|^registry\.access\.redhat\.com/ubi9/ubi-minimal([:@]|$)"
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
# Dockerfile frontends of the syntax directive the model follows: the official
# ones, stable or labs.
REVIEWED_FRONTEND = re.compile(
    r"^(docker\.io/)?docker/dockerfile(-upstream)?(:1(\.\d+)*(-labs)?)?(@sha256:[0-9a-f]{64})?$"
)
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
ASSIGNING_EXPANSION = re.compile(r"(?<!\\)\$\{[A-Za-z_][A-Za-z0-9_]*:?=")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
GLOB_CHARS = re.compile(r"[*?\[]")
HEREDOC = re.compile(r"<<-?\s*['\"]?[A-Za-z_]")
COMMAND_PREFIXES = frozenset({"exec", "command", "nohup", "time", "builtin"})
# Prefixes that are programs found on PATH, not shell builtins (time is a
# keyword of bash, a program for sh).
EXTERNAL_PREFIXES = frozenset({"env", "nohup", "sudo", "time"})
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
# Redirections that may write their target (<> opens it for reading and writing).
OUTPUT_REDIRECTIONS = frozenset({">", ">>", ">|", "&>", "&>>", "<>"})
# Devices that discard or print what is written to them: they hold no file.
DEVICE_FILES = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr"})
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
# A wildcard character that is quoted, escaped or not read by a shell (exec form)
# is literal: it is carried as a private-use character until a command that
# takes paths reads it as a bracket expression ([*] matches only "*").
QUOTED_GLOB = {"*": "\ue030", "?": "\ue031", "[": "\ue032"}
PLAIN_GLOB = str.maketrans({v: k for k, v in QUOTED_GLOB.items()})
LITERAL_GLOB = str.maketrans({v: f"[{k}]" for k, v in QUOTED_GLOB.items()})


def literal_globs(text):
    """``text`` with its wildcard characters taken literally."""
    return text.translate(str.maketrans(QUOTED_GLOB))


# The value of a variable the model does not follow, or the output of a command
# substitution: it keeps a "$", so a path built from it is reported, and it
# matches no variable reference.
UNKNOWN = "${...}"
VAR_MARKER = re.compile(f"([{VAR_UNQUOTED}{VAR_QUOTED}{VAR_SUBST}])(\\d+){VAR_END}")
# Commands that cannot delete, truncate, move or rewrite a file they name: they
# read it, create something new, or change its owner. A command the model
# neither interprets nor lists here is reported.
TOUCH_OPTIONS_WITH_VALUE = frozenset({"-d", "-r", "-t", "--date", "--reference"})
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
# Modules the site initialisation of python imports from its search path.
PYTHON_STARTUP_HOOKS = ("sitecustomize", "usercustomize")
# The files of a site-packages directory python runs at startup: a .pth file
# (its import lines) and the startup hooks.
SITE_STARTUP_FILE = re.compile(
    rf"(?:^{re.escape(SITE_PACKAGES)}|/(?:site|dist)-packages)"
    rf"/(?:[^/]+\.pth|(?:{'|'.join(PYTHON_STARTUP_HOOKS)})(?:\.py|/__init__\.py))$"
)
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
# Options of wget and curl the model reads: the ones naming a file they write
# ("file"), among them the response bodies placed in the directory option
# ("body"), the directory of the bodies and of the files named after the URL
# ("dir"), the ones taking a value without writing a file, and the flags. Any
# other option is reported: a configuration file, a cookie file or a recursive
# download may write files the model does not see.
DOWNLOADERS = {
    "wget": {
        "file": frozenset(
            {"-O", "--output-document", "-o", "--output-file", "-a", "--append-output"}
        ),
        # wget -P places the files named after the URL only, never -O.
        "body": frozenset(),
        "dir": frozenset({"-P", "--directory-prefix"}),
        "value": frozenset(
            {
                "-t",
                "--tries",
                "-T",
                "--timeout",
                "--header",
                "-U",
                "--user-agent",
                "--progress",
                "--user",
                "--password",
            }
        ),
        "flag": frozenset(
            {
                "-q",
                "--quiet",
                "-nv",
                "--no-verbose",
                "-nc",
                "--no-clobber",
                "-c",
                "--continue",
                "--no-check-certificate",
                "--https-only",
                "-S",
                "--server-response",
                "--show-progress",
                "-4",
                "--inet4-only",
                "-6",
                "--inet6-only",
            }
        ),
    },
    "curl": {
        "file": frozenset(
            {
                "-o",
                "--output",
                "-D",
                "--dump-header",
                "-c",
                "--cookie-jar",
                "--trace",
                "--trace-ascii",
                "--stderr",
            }
        ),
        # curl --output-dir places -o and -O, not the headers, traces or cookies.
        "body": frozenset({"-o", "--output"}),
        "dir": frozenset({"--output-dir"}),
        "value": frozenset(
            {
                "-H",
                "--header",
                "-X",
                "--request",
                "-d",
                "--data",
                "--data-raw",
                "--data-binary",
                "--data-urlencode",
                "-T",
                "--upload-file",
                "-u",
                "--user",
                "-A",
                "--user-agent",
                "-e",
                "--referer",
                "-b",
                "--cookie",
                "-C",
                "--continue-at",
                "-m",
                "--max-time",
                "--connect-timeout",
                "--retry",
                "--retry-delay",
                "--retry-max-time",
                "--proto",
                "--proto-redir",
                "--max-filesize",
                "--limit-rate",
                "--url",
            }
        ),
        "flag": frozenset(
            {
                "-f",
                "--fail",
                "--fail-with-body",
                "-s",
                "--silent",
                "-S",
                "--show-error",
                "-L",
                "--location",
                "-k",
                "--insecure",
                "-I",
                "--head",
                "-v",
                "--verbose",
                "-#",
                "--progress-bar",
                "--no-progress-meter",
                "--compressed",
                "-O",
                "--remote-name",
                "--remote-name-all",
                "-g",
                "--globoff",
                "-4",
                "--ipv4",
                "-6",
                "--ipv6",
                "--http1.1",
                "--http2",
                "--tlsv1.2",
                "--tlsv1.3",
                "--ssl-reqd",
                "-N",
                "--no-buffer",
                "--create-dirs",
                "--retry-all-errors",
                "-q",
                "--disable",
            }
        ),
    },
}
# Configuration files wget and curl read by default, and the variables that
# move them.
DOWNLOADER_CONFIGS = {
    "wget": ({".wgetrc", "wgetrc"}, ("WGETRC", "SYSTEM_WGETRC")),
    "curl": ({".curlrc", "curlrc", "_curlrc"}, ("CURL_HOME", "XDG_CONFIG_HOME")),
}
GIT_CLONE_OPTIONS_WITH_VALUE = frozenset(
    {
        "-b",
        "--branch",
        "-o",
        "--origin",
        "-c",
        "--config",
        "-u",
        "--upload-pack",
        "-j",
        "--jobs",
        "--depth",
        "--reference",
        "--reference-if-able",
        "--template",
        "--filter",
        "--shallow-since",
        "--shallow-exclude",
        "--server-option",
    }
)
# External images whose files a COPY --from may take, reviewed for what they
# hold (by name, any tag or digest).
AUDITED_IMAGES = {
    "ghcr.io/astral-sh/uv": "the uv and uvx binaries, at the root of the image",
}


def audited_image(image):
    """``image``, without its tag or digest, is one of AUDITED_IMAGES."""
    name = image.split("@", 1)[0]
    # A colon after the last slash starts the tag (before it, a registry port).
    if name.rfind(":") > name.rfind("/"):
        name = name[: name.rfind(":")]
    return name in AUDITED_IMAGES


# Programs of base images or packages whose effect was reviewed: they write no
# connector file.
AUDITED_PROGRAMS = {
    "playwright": "downloads browsers into the cache of the user",
    "unogenerator_start": "starts the LibreOffice listener of export-file-ods",
}
# The only subcommands of an audited program the review covers: the others
# (playwright pdf, screenshot...) write files where they are told.
AUDITED_SUBCOMMANDS = {"playwright": {"install"}}
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
# pip commands that write nothing the image keeps (cache only changes the cache).
PIP_READ_ONLY_COMMANDS = frozenset(
    {
        "list",
        "show",
        "freeze",
        "check",
        "help",
        "hash",
        "debug",
        "inspect",
        "index",
        "search",
        "completion",
        "cache",
    }
)
# PIP_* variables that change no install location and no file pip writes.
PIP_REVIEWED_VARIABLES = frozenset(
    {
        "PIP_BREAK_SYSTEM_PACKAGES",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PIP_NO_CACHE_DIR",
        "PIP_CACHE_DIR",
        "PIP_DEFAULT_TIMEOUT",
        "PIP_TIMEOUT",
        "PIP_RETRIES",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PIP_TRUSTED_HOST",
        "PIP_NO_INPUT",
        "PIP_PROGRESS_BAR",
        "PIP_ROOT_USER_ACTION",
        "PIP_PREFER_BINARY",
        "PIP_QUIET",
        "PIP_VERBOSE",
    }
)
# Global pip options (before the command) that take a value.
PIP_GLOBAL_OPTIONS_WITH_VALUE = frozenset(
    {
        "--cache-dir",
        "--proxy",
        "--retries",
        "--timeout",
        "--exists-action",
        "--trusted-host",
        "--cert",
        "--client-cert",
        "--use-feature",
        "--use-deprecated",
        "--keyring-provider",
        "--root-user-action",
        "--progress-bar",
    }
)
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
# The archive names pip takes as a local file, slash or not (its ARCHIVE_EXTENSIONS).
PIP_ARCHIVE = re.compile(r"\.(whl|zip|tar(\.\w+)?|tgz|tbz|txz|tlz)$", re.IGNORECASE)
# The setuptools backends whose discovery and package data the model reads.
SETUPTOOLS_BACKENDS = frozenset(
    {"setuptools.build_meta", "setuptools.build_meta:__legacy__"}
)
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
        if current == SITE_PACKAGES:
            # The installed packages stand for site-packages, which sits deeper:
            # what lies above it in the model is not where pycti looks.
            break
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


def image_path(path, cwd, what="path", links=()):
    """Absolute image path of ``path``, relative to ``cwd``. A ``..`` after one of
    ``links`` (the links the build created) climbs from the target of the link,
    not from the link, so it is reported before ``..`` is collapsed."""
    if "$" in path or "`" in path:
        raise Unsupported(
            f"{what} '{path}' uses a variable or a command the build does not define"
        )
    if not path.startswith("/") and cwd is None:
        raise Unsupported(
            f"{what} '{path}' is relative to an unknown working directory"
        )
    joined = path if path.startswith("/") else posixpath.join(cwd, path)
    parts = joined.split("/")
    for index, part in enumerate(parts):
        if part != "..":
            continue
        prefix = posixpath.normpath("/".join(parts[:index]) or "/")
        for link in links:
            if prefix == link or prefix.startswith(link.rstrip("/") + "/"):
                raise Unsupported(
                    f"{what} '{path}' climbs out of the link {link} the build created"
                )
    normalized = posixpath.normpath(joined)
    # Linux reads two leading slashes as one; normpath keeps them.
    return "/" + normalized.lstrip("/")


def path_candidates(command, value, links=()):
    """Image paths PATH ``value`` gives a bare ``command``, in lookup order, with
    ``.`` and ``..`` resolved as for any other path; None for an entry the model
    does not resolve (relative, or built from a value it does not know)."""
    for directory in value.split(":"):
        if not directory.startswith("/") or "$" in directory or "`" in directory:
            yield None
            continue
        yield image_path(posixpath.join(directory, command), "/", "PATH entry", links)


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


def glob_regex(pattern, globstar=True):
    """Translate a Docker path pattern into a regular expression. ``globstar``:
    ``**`` crosses directories (.dockerignore, COPY --exclude); COPY sources use
    Go's filepath.Match, where it is two ``*``."""
    out = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if globstar and pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if globstar and pattern.startswith("**", i):
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
            # Go negates a class with "^" only: "[!x]" matches "!" or "x".
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
        if current == UNKNOWN:
            # Set or not, to a value the model does not follow: no default applies.
            return match.group(0)
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
        directive = (
            re.match(r"#\s*([a-zA-Z]+)\s*=\s*(\S*)", stripped) if directives else None
        )
        if directive and directive.group(1).lower() == "escape":
            raise Unsupported("the escape parser directive")
        if directive and directive.group(1).lower() == "syntax":
            # Another frontend may read the instructions differently.
            if not REVIEWED_FRONTEND.match(directive.group(2)):
                raise Unsupported(f"the Dockerfile frontend {directive.group(2)}")
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


def first_word(text):
    """The first word of ``text`` and the rest, split on any blank."""
    parts = text.split(None, 1)
    return (parts[0], parts[1] if len(parts) > 1 else "") if parts else ("", "")


def split_copy_args(arguments):
    """Flags (name -> list of values), sources and destination of a COPY / ADD."""
    flags = {}
    rest = arguments.strip()
    while rest.startswith("--"):
        token, rest = first_word(rest)
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
            # A symbolic link is copied as a link: where it points is not modelled.
            links = [d for d in subdirs if (Path(directory) / d).is_symlink()]
            subdirs[:] = sorted(d for d in subdirs if d != ".git" and d not in links)
            for name in sorted([*names, *links]):
                path = Path(directory) / name
                rel = path.relative_to(connector_dir).as_posix()
                if not ignored_by(rel, rules):
                    kind = "link" if path.is_symlink() else "context"
                    self.files[rel] = (kind, rel)
        self.stamps = written_stamps(connector_dir)
        for rel in self.stamps:
            # The build step writes through a link: where the stamp lands, and
            # what the copy ships, are not modelled.
            linked = [
                parent
                for parent in [connector_dir / rel, *(connector_dir / rel).parents]
                if parent != connector_dir
                and connector_dir in parent.parents
                and parent.is_symlink()
            ]
            if linked:
                raise Unsupported(f"the stamp {rel} is written through a symbolic link")
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

    def is_archive(self, rel):
        """ADD extracts a local tar archive, compressed or not, whatever its name,
        and copies any other file as it is: Docker tells them apart by content."""
        origin = self.files.get(rel)
        if origin is None or origin[0] == "stamp":
            return False
        if origin[0] == "link":
            # The archive test reads the file the link points to.
            return True
        path = self.root / rel
        with open(path, "rb") as handle:
            head = handle.read(4)
        if head == b"\x28\xb5\x2f\xfd":
            # zstd, which Docker decompresses and this Python may not read.
            return True
        # Old tar headers without the ustar magic, plain or gzip, bzip2, xz.
        return tarfile.is_tarfile(path)

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
    # (command, shell form) of the HEALTHCHECK of the image, if any.
    healthcheck: tuple = None
    # The external image the stage starts from, through the stages it builds on.
    base: str = None
    # This stage declared a CMD (one inherited from the parent does not count).
    cmd_set: bool = False
    # Links a build command created: path -> what it stands for (None: unknown).
    links: dict = field(default_factory=dict)
    # Directories below which a COPY put content the model does not know.
    unknown_dirs: set = field(default_factory=set)
    # Directories only a mkdir that may not have run created (in a branch the
    # model does not follow).
    uncertain_dirs: set = field(default_factory=set)

    def written(self, path):
        """``path`` holds what a build step wrote, with a content the model does
        not know: it is such a path, or lies below one (a moved or linked
        directory, a directory a COPY filled)."""
        for region in (*self.replaced, *self.unknown_dirs):
            if path == region or path.startswith(region.rstrip("/") + "/"):
                return True
            # A pattern a command wrote through (mv /tmp/tools/* /opt/bin/).
            if GLOB_CHARS.search(region) and any(
                shell_glob_match(region, p) for p in self_and_parents(path)
            ):
                return True
        return False

    def child(self):
        # ENV values are part of the image. Whether a stage built on this one
        # keeps its ARG values depends on the builder version: not known.
        return Stage(
            workdir=self.workdir,
            files=dict(self.files),
            dirs=set(self.dirs),
            variables={
                **{key: UNKNOWN for key in self.variables if key not in self.env},
                **self.env,
            },
            env=dict(self.env),
            shell=list(self.shell),
            entrypoint=self.entrypoint,
            cmd=self.cmd,
            volumes=list(self.volumes),
            replaced=set(self.replaced),
            healthcheck=self.healthcheck,
            base=self.base,
            unknown_dirs=set(self.unknown_dirs),
            uncertain_dirs=set(self.uncertain_dirs),
            links=dict(self.links),
        )

    def add_file(self, path, origin):
        self.files[path] = origin
        for parent in self_and_parents(posixpath.dirname(path)):
            self.dirs.add(parent)

    def is_dir(self, path):
        prefix = path.rstrip("/") + "/"
        if path in self.dirs or any(f.startswith(prefix) for f in self.files):
            return True
        if path in self.uncertain_dirs:
            # A copy lands inside it or replaces it: where its files go is not known.
            raise Unsupported(
                f"{path} is a directory only if a mkdir that may not run did"
            )
        return False


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
# The directories between such a site-packages and its prefix.
NATIVE_SITE_PARENT = re.compile(
    r"^(?:/usr(?:/local)?|/opt/[^/]+|/[^/]*venv[^/]*)(?:/lib(?:64)?(?:/python3(?:\.\d+)?)?)?$"
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


def pattern_reaches(pattern, path):
    """The wildcard ``pattern`` (absolute) expands through ``path``: its first
    components, as many as ``path`` has, match it."""
    if not GLOB_CHARS.search(pattern):
        return False
    parts = pattern.split("/")
    depth = len(path.rstrip("/").split("/"))
    return len(parts) >= depth and shell_glob_match("/".join(parts[:depth]), path)


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


def remove_dirs(dirs, target):
    """Delete the directory ``target`` (absolute, wildcards allowed) and every
    directory below it."""
    for modelled in modelled_targets(target):
        for path in list(dirs):
            if any(
                (
                    shell_glob_match(modelled, candidate)
                    if GLOB_CHARS.search(modelled)
                    else candidate == modelled
                )
                for candidate in self_and_parents(path)
            ):
                dirs.discard(path)


def removes_directories(args):
    """rm -r, -R or -d (or their long forms) removes directories too; a plain rm
    fails on a directory and leaves it in place."""
    for arg in args:
        if arg == "--":
            break
        if arg in ("--recursive", "--dir"):
            return True
        if (
            arg.startswith("-")
            and not arg.startswith("--")
            and set(arg[1:]) & set("rRd")
        ):
            return True
    return False


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
        backend = data.get("build-system", {}).get("build-backend")
        if backend is not None and backend not in SETUPTOOLS_BACKENDS:
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
        elif packages is None and ("py-modules" in tool or "py_modules" in tool):
            # Modules named explicitly turn automatic discovery off: no package.
            self.packages = []
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
        elif parser.has_option("options", "py_modules"):
            # Modules named explicitly turn automatic discovery off: no package.
            self.packages = []
        if parser.has_option("options", "package_dir"):
            self.unsupported = self.unsupported or "package_dir of setuptools"

    @property
    def automatic(self):
        """Whether setuptools discovers the packages itself: no packages, find
        or modules option given."""
        return self.packages is None and self.namespaces is None

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
    """A chmod after which everyone can still read (and, for a directory,
    search): an octal mode with these bits, or symbolic clauses that never take
    them away, whether they add permissions or set them explicitly."""
    modes = [a for a in args if a not in CHMOD_OPTIONS]
    if not modes:
        return True
    mode = modes[0]
    if re.fullmatch(r"[0-7]{3,4}", mode):
        needed = 5 if search else 4
        return all(int(digit) & needed == needed for digit in mode[-3:])
    # What a file had before is enough, as for a copy without a mode.
    kept = {(who, bit): True for who in "ugo" for bit in "rx"}
    for clause in mode.split(","):
        parsed = re.fullmatch(r"([ugoa]*)((?:[-+=][rwxXst]*)+)", clause)
        if not parsed:
            # g=u and the other forms copying a class are not followed.
            return False
        classes = parsed.group(1).replace("a", "ugo") or "ugo"
        for operator, perms in re.findall(r"([-+=])([rwxXst]*)", parsed.group(2)):
            # X is the search permission of a directory.
            given = {"r": "r" in perms, "x": "x" in perms or "X" in perms}
            for who in classes:
                for bit, present in given.items():
                    if operator == "=":
                        kept[who, bit] = present
                    elif present:
                        kept[who, bit] = operator == "+"
    return all(kept[who, bit] for who in "ugo" for bit in ("rx" if search else "r"))


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
            flags = ""
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
                    flags += letter
            if flags:
                # The other options of the cluster stay for the command (ln -s).
                rest.append(f"-{flags}")
        else:
            rest.append(arg)
        i += 1
    return target, no_target, rest


def continues_line(line):
    """Whether a shell line goes on with the next one: it ends with a backslash
    that is not escaped by another, not between single quotes and not in a
    comment (a quote left open is reported when the line is read)."""
    quote = None
    i = 0
    while i < len(line):
        char = line[i]
        if quote == "'":
            if char == "'":
                quote = None
        elif char == "\\":
            if i + 1 == len(line):
                return True
            i += 1
        elif quote == '"':
            if char == '"':
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "#" and (
            i == 0 or line[i - 1].isspace() or line[i - 1] in ";&|()"
        ):
            return False
        i += 1
    return False


def braced_end(line, opening):
    """Index of the "}" closing the "{" at ``opening``, nested braces counted and
    escapes skipped; the last index of the line when it is not closed."""
    depth = 0
    i = opening
    while i < len(line):
        char = line[i]
        if char == "\\":
            i += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(line) - 1


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
    """The module of ``python -m`` (also written ``-mNAME``) and the arguments
    after it, or (None, [])."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-" or not arg.startswith("-"):
            return None, []
        if arg.startswith("--"):
            i += 2 if arg in PYTHON_OPTIONS_WITH_VALUE else 1
            continue
        cluster = arg[1:]
        for position, letter in enumerate(cluster):
            rest = cluster[position + 1 :]
            if letter == "c":
                return None, []
            if letter == "m":
                if rest:
                    return rest, args[i + 1 :]
                if i + 1 < len(args):
                    return args[i + 1], args[i + 2 :]
                return None, []
            if letter in "WX":
                if not rest:
                    i += 1
                break
        i += 1
    return None, []


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
    table = DOWNLOADERS[program]
    with_value = table["file"] | table["dir"] | table["value"]
    outputs, bodies, urls = [], [], []
    directory = None
    remote_name = program == "wget"
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            urls.extend(args[i:])
            break
        if not arg.startswith("-") or arg == "-":
            urls.append(arg)
            continue
        if arg.startswith("--"):
            option, sep, value = arg.partition("=")
            pairs = [(option, value if sep else None)]
        elif arg in table["flag"] or arg in with_value:
            pairs = [(arg, None)]
        else:
            # Short options in a cluster: one taking a value takes the rest.
            pairs = []
            for position, letter in enumerate(arg[1:], 2):
                pairs.append((f"-{letter}", arg[position:] or None))
                if f"-{letter}" in with_value:
                    break
                pairs[-1] = (f"-{letter}", None)
        for option, value in pairs:
            if option in table["flag"]:
                if option in ("-O", "--remote-name", "--remote-name-all"):
                    # curl: the file takes the name of the URL.
                    remote_name = True
                continue
            if option not in with_value:
                raise Unsupported(
                    f"{program} {option}: its effect on the files is not known"
                )
            if value is None:
                if i >= len(args):
                    raise Unsupported(f"{program} {option} without a value")
                value = args[i]
                i += 1
            if option in table["file"]:
                (bodies if option in table["body"] else outputs).append(value)
                if program == "wget" and option in ("-O", "--output-document"):
                    remote_name = False
            elif option in table["dir"]:
                directory = value
            elif option == "--url":
                urls.append(value)
    if remote_name:
        for url in urls:
            bodies.append(
                posixpath.basename(url.split("://", 1)[-1].split("?")[0])
                or "index.html"
            )
    # The directory applies whatever its place among the options.
    for body in bodies:
        if body == "-" or directory is None:
            outputs.append(body)
        elif body.startswith("/"):
            raise Unsupported(
                f"{program} {body} with an output directory: where it lands is not modelled"
            )
        else:
            outputs.append(posixpath.join(directory, body))
    return [output for output in outputs if output != "-"]


def split_option(words):
    """``words`` with an attached pip option value split off: -e./x,
    --editable=./x, -rx.txt, --requirement=x.txt, -cx.txt, --constraint=x."""
    if not words:
        return words
    first = words[0]
    for short, long in (
        ("-e", "--editable"),
        ("-r", "--requirement"),
        ("-c", "--constraint"),
    ):
        if first.startswith(long + "="):
            return [long, first[len(long) + 1 :], *words[1:]]
        if first.startswith(short) and len(first) > 2 and not first.startswith("--"):
            return [short, first[2:], *words[1:]]
    return words


def check_shell_options(options):
    """Options of a shell the model reads its scripts with: -c, and the ones
    that only stop it on errors or trace it (-e, -u, -x, -o pipefail...)."""
    i = 0
    while i < len(options):
        option = options[i]
        if option in ("-o", "+o") and i + 1 < len(options):
            if options[i + 1] not in ("pipefail", "errexit", "nounset", "xtrace"):
                raise Unsupported(f"shell option {option} {options[i + 1]}")
            i += 2
            continue
        if not re.fullmatch(r"[-+][ceuxv]+", option):
            # -O dotglob, -l (profile files), -B, ... change what commands do.
            raise Unsupported(f"shell option {option}")
        i += 1


def check_shell_environment(program, env):
    """bash runs the file of BASH_ENV before any script it is not interactive for,
    and turns on the options BASHOPTS and SHELLOPTS list (dotglob, noglob...)."""
    if posixpath.basename(program or "") != "bash":
        return
    for name in ("BASH_ENV", "BASHOPTS", "SHELLOPTS"):
        if env.get(name):
            raise Unsupported(f"bash with {name} set")


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
        elif option == "--":
            words = words[1:]
            break
        else:
            # --split-string and others change which command runs.
            raise Unsupported(f"env {option}")
    return words, assigned, unset


def interpreter_of(text, model=None, env=None, files=None, stage=None):
    """Program named by the interpreter line of a script, or an empty string.
    With the image model, the interpreter (and the program ``env`` looks up)
    must not be a file the build wrote."""
    if not text or not text.startswith("#!"):
        return ""
    interpreter = text.splitlines()[0][2:].split()
    if not interpreter:
        return ""
    programs = [interpreter[0]]
    if PYTHON.match(posixpath.basename(interpreter[0])) and len(interpreter) > 1:
        # The kernel hands python the rest of the line as one argument, an option
        # that may change what runs (-mNAME, -c) and where it is looked up.
        raise Unsupported(f"interpreter line '{text.splitlines()[0]}'")
    if posixpath.basename(interpreter[0]) in SHELLS:
        check_shell_options(interpreter[1:])
    if posixpath.basename(interpreter[0]) == "env":
        # The kernel hands env the rest of the line as one argument: only a
        # lone program name is read as such (env -S splits it, and then the
        # program runs with arguments of its own).
        rest = interpreter[1:]
        if len(rest) != 1 or rest[0].startswith("-") or ASSIGNMENT.match(rest[0]):
            raise Unsupported(f"interpreter line '{text.splitlines()[0]}'")
        programs.append(rest[0])
    if model is not None:
        for program in programs:
            if model.shadow(program, env or {}, files, stage, "/"):
                raise Unsupported(
                    f"interpreter {program} of a script is a file the build wrote"
                )
    return posixpath.basename(programs[-1])


def shell_script(args, cwd, files, model, stage=None):
    """What a shell started with ``args`` runs: its ``-c`` string or a script
    file of the image model; None when it reads its standard input."""
    i = 0
    while i < len(args) and args[i].startswith(("-", "+")):
        option = args[i]
        if not option.startswith("--") and "c" in option[1:]:
            if i + 1 >= len(args):
                raise Unsupported("'sh -c' without a command")
            check_shell_options(args[: i + 1])
            return args[i + 1]
        i += 2 if option in ("-o", "+o") else 1
    check_shell_options(args[:i])
    if i >= len(args):
        return None
    path = image_path(
        args[i],
        cwd,
        "shell script",
        stage.links if stage is not None else model.final.links,
    )
    # Below a mount or another path of unknown content, the file is not the
    # one the model has.
    unknown = stage is not None and stage.written(path)
    text = None if unknown else model.context.read(files.get(path))
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
        # The environment of the shell is exported; a plain assignment is not,
        # unless set -a is on.
        self.exported = set(variables)
        self.allexport = False
        self.start = start
        self.nesting = nesting
        self.stack = []
        self.processes = []
        self.ended = False
        # Variable references of the script, in the order the markers number them.
        self.references = []
        # Commands of the command substitutions, run once before their command.
        self.substitutions = []
        # What the commands of the current && / | list changed (see _end_chain).
        self.chain_variables = set()
        self.chain_directory = False
        self.chain_dirs = set()
        # The current list has a ||, a !, a pipeline or a background job: its
        # status does not tell that every command of it ran and succeeded.
        self.chain_partial = False
        # Directories the commands after && of the last list created: they exist
        # if that list ends the script of a RUN, whose build fails unless it
        # succeeds, and may be missing once another command runs.
        self.pending_dirs = set()
        # The script of a RUN instruction (see pending_dirs).
        self.build_step = False
        # This shell, or the command it runs, is a pipeline part or a background
        # job: it runs next to the other commands of the script.
        self.alongside = False
        self.command_alongside = False

    def run(self, script):
        if self.nesting > 8:
            raise Unsupported("shell scripts nested too deeply")
        tokens = []
        for line in self._lines(script):
            if HEREDOC.search(line):
                raise Unsupported("a here-document in a shell script")
            tokens += self._tokens(line)
            # A list or a pipeline whose operator ends the line goes on with the
            # next line, as with a backslash.
            if tokens and tokens[-1] in ("&&", "||", "|"):
                continue
            self._statements(tokens + ["\n"])
            tokens = []
            if self.ended:
                break
        if tokens:
            self._statements(tokens + ["\n"])
        if not self.build_step:
            self._uncertain(self.pending_dirs)
        return self.processes

    def _uncertain(self, dirs):
        """``dirs`` exist only if a command that may not have run created them."""
        for directory in dirs:
            self.stage.dirs.discard(directory)
            self.stage.uncertain_dirs.add(directory)
        self.pending_dirs -= set(dirs)

    def _expand(self, word, split=True):
        """Words of ``word`` once its variables are expanded with the current
        values; an unquoted expansion is split on blanks."""
        unquoted = False

        def substitute(match):
            nonlocal unquoted
            if match.group(1) == VAR_SUBST:
                # Unknown output: a "$" stays, so a path built from it is reported.
                return UNKNOWN
            unquoted = unquoted or match.group(1) == VAR_UNQUOTED
            value = expand(self.references[int(match.group(2))], self.variables)
            # The wildcard characters of a quoted expansion are literal.
            return value if match.group(1) == VAR_UNQUOTED else literal_globs(value)

        value = VAR_MARKER.sub(substitute, word)
        if split and unquoted and "IFS" in self.variables:
            raise Unsupported("word splitting with IFS set")
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
        nested.alongside = self.alongside or self.command_alongside
        return nested

    def _launch(self, words, env, conditional):
        if conditional:
            raise Unsupported(
                "the connector started inside a conditional or a loop of the entry script"
            )
        if self.alongside or self.command_alongside:
            # The commands next to it may change its files while it starts.
            raise Unsupported(
                "the connector started in a pipeline or a background job of the entry script"
            )
        if self.model.foreign_effects:
            raise Unsupported(
                "a python process starts after another one whose effects on the files are not modelled"
            )
        self.processes.extend(
            self.model.launch(words, self.cwd, env, self.files, self.nesting + 1)
        )
        # What this process does to the files, for any process started after it
        # (an exec in a nested shell does not end this one), is not known.
        self.model.foreign_effects = True

    @staticmethod
    def _lines(script):
        lines = []
        current = ""
        for raw in script.splitlines():
            line = current + raw
            if continues_line(line):
                current = line[:-1]
                continue
            lines.append(line)
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
                if arithmetic and re.search(r"(?<![=!<>])=(?!=)|\+\+|--", inner):
                    raise Unsupported("an arithmetic expansion that assigns a variable")
                if arithmetic and ("$(" in inner or "`" in inner):
                    raise Unsupported(
                        "a command substitution in an arithmetic expansion"
                    )
                out.append(f"{VAR_SUBST}{len(self.substitutions)}{VAR_END}")
                self.substitutions.append(None if arithmetic else inner)
                i = end + 1
                continue
            if quote != "'" and char == "`":
                raise Unsupported("a backquoted command substitution")
            if quote is None and char in "<>" and line.startswith("(", i + 1):
                raise Unsupported("a process substitution")
            if quote is None and char == "{" and (i == 0 or line[i - 1] != "$"):
                # bash (the sh of some base images) expands {a,b} and {1..3}.
                end = line.find("}", i)
                inner = line[i + 1 : end] if end > i else ""
                if ("," in inner or ".." in inner) and not any(
                    c.isspace() for c in inner
                ):
                    raise Unsupported("a brace expansion")
            if quote != "'" and line.startswith("${", i):
                expansion = line[i : braced_end(line, i + 1) + 1]
                if ASSIGNING_EXPANSION.search(expansion):
                    # ${NAME:=word} and ${NAME=word} set the variable as well.
                    raise Unsupported("a parameter expansion that assigns a variable")
            reference = (
                VARIABLE.match(line, i) if char == "$" and quote != "'" else None
            )
            if reference:
                if "$(" in reference.group(0) or "`" in reference.group(0):
                    raise Unsupported(
                        "a command substitution inside a parameter expansion"
                    )
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
                    following = line[i + 1]
                    out.append(
                        char
                        + QUOTED_GLOB.get(following, PROTECT.get(following, following))
                    )
                    i += 1
                else:
                    # A quoted wildcard character is literal.
                    out.append(QUOTED_GLOB.get(char, PROTECT.get(char, char)))
            elif char in ("'", '"'):
                quote = char
                out.append(char)
            elif char == "\\" and i + 1 < len(line):
                following = line[i + 1]
                if following in QUOTED_GLOB:
                    out.append(QUOTED_GLOB[following])
                else:
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
        # Targets read or duplicated, not written: their command substitutions
        # still run before the command.
        reads = []
        before = None
        skip = False
        redirect = None
        for token in tokens:
            if redirect is not None and token not in SEPARATORS:
                target = token.translate(RESTORE)
                if redirect in OUTPUT_REDIRECTIONS or (
                    redirect == ">&" and not target.isdigit() and target != "-"
                ):
                    writes.append(target)
                else:
                    reads.append(target)
                redirect = None
                continue
            redirect = None
            if token in SEPARATORS:
                if (words or writes or reads) and not skip:
                    self._command(words, writes, before, token, reads)
                words, writes, reads, skip = [], [], [], False
                before = token if token != "\n" else None
                if token not in ("&&", "||", "|"):
                    self._end_chain()
                if self.ended:
                    return
                continue
            if skip:
                if skip == "for":
                    # The loop variable takes values the model does not follow.
                    self.variables[token.translate(RESTORE)] = UNKNOWN
                    skip = True
                self._substitute([token], True)
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
                if token == "(" and len(words) == 1 and not writes:
                    # name() { ...; }: the body runs where the function is called,
                    # with that working directory, under a name it may shadow.
                    raise Unsupported("a shell function")
                if words or writes or reads:
                    self._command(words, writes, before, token, reads)
                    words, writes, reads = [], [], []
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
                if token == "!":
                    self.chain_partial = True
                if token in ("then", "do", "else", "elif", "!", "in"):
                    continue
                if token == "function":
                    raise Unsupported("a shell function")
            words.append(token.translate(RESTORE))
        if (words or writes or reads) and not skip:
            self._command(words, writes, before, None, reads)
        self._end_chain()

    def _end_chain(self):
        """End of an && / || / | list: what a command that may not have run (after
        &&) or ran in a subshell (a pipeline part, a background job) changed is no
        longer known to the commands after the list. A directory such a command
        created may be missing (see pending_dirs): a later cd into it may fail, a
        COPY into it is reported."""
        for key in self.chain_variables:
            self.variables[key] = UNKNOWN
        if self.chain_directory:
            self._unknown_directory(
                "a directory change in an && list, a pipeline or a background job"
            )
        if self.chain_partial:
            self._uncertain(self.chain_dirs)
        else:
            self.pending_dirs |= self.chain_dirs
        self.chain_variables = set()
        self.chain_directory = False
        self.chain_dirs = set()
        self.chain_partial = False

    def exec_form(self, argv):
        """A command of the exec form: no shell reads it, so each word is an
        argument as written, wildcard characters and operators included."""
        self._command([literal_globs(word) for word in argv], [], None, None)
        self._end_chain()

    def _command(self, words, writes, before, after, reads=()):
        # A command runs after the last list, which may have failed.
        self._uncertain(self.pending_dirs)
        if before in ("||", "|") or after in ("||", "|", "&"):
            self.chain_partial = True
        uncertain = before in ("&&", "|") or after in ("|", "&")
        if not uncertain:
            self._simple_command(words, writes, before, after, reads)
            return
        variables, cwd, dirs = dict(self.variables), self.cwd, set(self.stage.dirs)
        self._simple_command(words, writes, before, after, reads)
        self.chain_variables |= {
            key
            for key in {*variables, *self.variables}
            if variables.get(key) != self.variables.get(key)
        }
        self.chain_directory = self.chain_directory or self.cwd != cwd
        self.chain_dirs |= self.stage.dirs - dirs

    def _set_options(self, args):
        """set -a / +a (and -o / +o allexport): assignments exported or not."""
        for index, arg in enumerate(args):
            if arg in ("-o", "+o") and args[index + 1 : index + 2] == ["allexport"]:
                self.allexport = arg == "-o"
            elif re.fullmatch(r"[-+][a-zA-Z]+", arg) and "a" in arg:
                self.allexport = arg.startswith("-")

    def _substitute(self, words, conditional):
        """Run the command substitutions of ``words``: their commands run before
        the command that uses their output."""
        for word in words:
            for match in VAR_MARKER.finditer(word):
                index = int(match.group(2))
                if match.group(1) == VAR_SUBST and self.substitutions[index]:
                    script, self.substitutions[index] = self.substitutions[index], None
                    # A subshell: the same variables, exported or not.
                    nested = self._nested(
                        self.files,
                        self.cwd,
                        dict(self.variables),
                        self.start,
                        conditional,
                    )
                    nested.exported = set(self.exported)
                    nested.allexport = self.allexport
                    nested.run(script)

    def _simple_command(self, words, writes, before, after, reads=()):
        conditional = bool(self.stack) or before == "||"
        self.command_alongside = "|" in (before, after) or after == "&"
        self._substitute((*words, *writes, *reads), conditional)
        for target in writes:
            # Truncated or rewritten: the file no longer holds what the model knows.
            [value] = self._expand(target, split=False)
            value = value.translate(PLAIN_GLOB)
            path = self._path(value, "redirection target")
            self._through_link(path)
            if path in DEVICE_FILES:
                continue
            remove_files(self.files, path)
            self.stage.replaced.add(path)
        assigned = {}
        while words and ASSIGNMENT.match(words[0]):
            key, _, value = words[0].partition("=")
            [assigned[key]] = self._expand(value, split=False)
            assigned[key] = assigned[key].translate(PLAIN_GLOB)
            if all(ASSIGNMENT.match(w) for w in words):
                # Assignments alone apply one after the other; in a branch the model
                # does not follow, the variable is no longer known.
                if conditional:
                    self.variables[key] = UNKNOWN
                else:
                    self.variables[key] = assigned[key]
                if self.allexport:
                    self.exported.add(key)
            words = words[1:]
        if not words:
            return
        words = [part for word in words for part in self._expand(word)]
        if not words:
            return
        if "GLOBIGNORE" in {**self.variables, **assigned} and any(
            GLOB_CHARS.search(word) for word in words
        ):
            # bash: a wildcard then also matches a leading dot.
            raise Unsupported("a wildcard with GLOBIGNORE set")
        handed_over = False
        external_prefix = False
        unset = set()
        while words:
            name = posixpath.basename(words[0])
            external = name in EXTERNAL_PREFIXES or "/" in words[0]
            if external and self.model.shadow(
                words[0],
                {**self.variables, **assigned},
                self.files,
                self.stage,
                self.cwd,
            ):
                # A wrapper the build wrote under this name runs instead.
                break
            if name == "command" and words[1:2] and words[1] in ("-v", "-V"):
                # command -v: a lookup, nothing runs.
                return
            if name in COMMAND_PREFIXES:
                handed_over = handed_over or name == "exec"
                external_prefix = external_prefix or external
                words = words[1:]
            elif name == "env":
                external_prefix = True
                words, assigned, unset = env_prefix(words[1:], assigned, unset)
            elif name == "sudo":
                raise Unsupported(
                    "sudo: the environment, PATH and working directory of the command are not modelled"
                )
            else:
                break
        if not words:
            return
        in_pipeline = before == "|" or after == "|"
        # Commands taking paths read a literal wildcard character as such; the
        # others receive the characters the shell passes.
        literal_args = [word.translate(LITERAL_GLOB) for word in words[1:]]
        words = [word.translate(PLAIN_GLOB) for word in words]
        assigned = {key: value.translate(PLAIN_GLOB) for key, value in assigned.items()}
        name = posixpath.basename(words[0])
        args = words[1:]
        # Only a name the shell runs itself can be one of its builtins: a path,
        # or a command env, nohup or time start, is a program of the image.
        shell_command = "/" not in words[0] and not external_prefix
        # The shell looks the command up with all its variables; the command
        # receives the exported ones and its own assignments.
        lookup = {
            key: value
            for key, value in {**self.variables, **assigned}.items()
            if key not in unset
        }
        env = {
            key: value
            for key, value in {
                **{k: v for k, v in self.variables.items() if k in self.exported},
                **assigned,
            }.items()
            if key not in unset
        }
        # A command after && may not run; a pipeline part or a background job runs
        # in a subshell. An exec or an exit there may leave the script going on.
        ends_script = before != "&&" and not in_pipeline and after != "&"
        if self.start and handed_over:
            # exec: the command replaces the script.
            self._launch(words, env, conditional)
            self.ended = ends_script
            return
        if shell_command and name == "export":
            for arg in args:
                if arg.startswith("-"):
                    if arg != "-p":
                        raise Unsupported(f"'export {arg}'")
                    continue
                key, sep, value = arg.partition("=")
                self.exported.add(key)
                if not sep:
                    continue
                if conditional:
                    # A branch the model does not follow may or may not have run.
                    self.variables[key] = UNKNOWN
                else:
                    self.variables[key] = value
            return
        if shell_command and name == "unset":
            for arg in args:
                if arg.startswith("-"):
                    continue
                if conditional:
                    self.variables[arg] = UNKNOWN
                else:
                    self.variables.pop(arg, None)
                    self.exported.discard(arg)
            return
        if shell_command and name == "set":
            self._set_options(args)
        builtin = shell_command and name in SHELL_BUILTINS
        if not builtin and self.model.shadow(
            words[0], lookup, self.files, self.stage, self.cwd
        ):
            # The file the build put on PATH under this name runs, not the
            # program the model knows by that name.
            if not self._executed_script(words, env, conditional):
                raise Unsupported(
                    f"'{name}' resolves on PATH to a file the build wrote, which the model does not know"
                )
            return
        if shell_command and name == "cd":
            self._cd(args, conditional, in_pipeline, lookup, after)
        elif shell_command and name in ("pushd", "popd"):
            self._unknown_directory(f"'{name}'")
        elif shell_command and name == "eval":
            raise Unsupported("'eval': the commands it runs are not known")
        elif shell_command and name in (".", "source"):
            if self.start:
                raise Unsupported(f"'{name}' in the entry script")
            self._source(name, args)
        elif name in ("rm", "unlink"):
            self._delete(
                self._operands(literal_args),
                directories=name == "rm" and removes_directories(literal_args),
            )
        elif name == "mv":
            self._move(literal_args)
        elif name == "ln":
            self._link(literal_args)
        elif name == "find":
            self._find(args)
        elif name in SHELLS:
            check_shell_environment(name, env)
            self._nested_shell(args, conditional, env)
        elif PIP.match(name):
            self._pip(args, conditional, env)
        elif name == "uv":
            self._uv(args, conditional, env)
        elif PYTHON.match(name):
            self._python(words, env, conditional)
        elif shell_command and name in ("exit", "return"):
            if not conditional and ends_script:
                self.ended = True
        elif not self._executed_script(words, env, conditional):
            self._other_command(words, literal_args, env, conditional)

    def _python_path(self, env):
        """The PYTHONPATH directories of a python process of the build, None for
        a relative one in an unknown working directory."""
        value = env.get("PYTHONPATH", "")
        if not value:
            return []
        entries = []
        for entry in value.split(":"):
            if "$" in entry:
                # Set in a branch the model does not follow, or from a variable
                # it does not know: any directory may come first.
                raise Unsupported(
                    "python run at build time with a PYTHONPATH the model does not resolve"
                )
            if not entry.startswith("/") and self.cwd is None:
                entries.append(None)
            else:
                # An empty entry is the working directory.
                entries.append(
                    image_path(
                        entry or ".", self.cwd, "PYTHONPATH entry", self.stage.links
                    )
                )
        return entries

    def _written_module(self, name, directories):
        """A file the build wrote that imports as module ``name`` from one of
        ``directories`` (None for a directory the model does not know)."""
        written = (*self.files, *self.stage.replaced)
        for directory in directories:
            if directory is None:
                if any(
                    posixpath.basename(p) in (name, f"{name}.py")
                    or p.endswith(f"/{name}/__init__.py")
                    for p in written
                ):
                    return f"{name} in a directory the model does not know"
                continue
            # A module file or a regular package; a directory without
            # __init__.py loses to the module of the interpreter.
            module, package = f"{directory}/{name}.py", f"{directory}/{name}"
            initializer = f"{package}/__init__.py"
            if module in self.files or initializer in self.files:
                return module if module in self.files else package
            if self.stage.written(module):
                return module
            if self.stage.written(package) or self.stage.written(initializer):
                return package
        return None

    def _module_shadow(self, name, env):
        """A file the build wrote that python -m ``name`` imports before the module
        of the interpreter (the working directory and PYTHONPATH come first)."""
        return self._written_module(name, [self.cwd, *self._python_path(env)])

    def _check_startup_hooks(self, env):
        """Before the code it is asked to run, python imports sitecustomize and
        usercustomize from PYTHONPATH and site-packages, and runs the import lines
        of the .pth files of site-packages: one the build wrote runs code the
        model does not know. The working directory is not searched yet."""
        directories = self._python_path(env)
        for hook in PYTHON_STARTUP_HOOKS:
            found = self._written_module(hook, directories)
            if found:
                raise Unsupported(
                    f"python run at build time imports {found}, a file the build wrote, at startup"
                )
        for path in (*self.files, *self.stage.replaced):
            if SITE_STARTUP_FILE.search(path):
                raise Unsupported(
                    f"python run at build time runs {path}, a file the build wrote, at startup"
                )

    def _python(self, words, env, conditional):
        """python at build time or in a start script."""
        args = words[1:]
        if not self.start:
            self._check_startup_hooks(env)
        module, module_args = python_module(args)
        if module is not None and not self.start:
            shadow = self._module_shadow(module.split(".")[0], env)
            if shadow:
                raise Unsupported(
                    f"python -m {module} may run {shadow}, a file the build wrote, instead of the module of the interpreter"
                )
        if module == "pip":
            self._pip(module_args, conditional, env)
            return
        if self.start:
            self._launch(words, env, conditional)
            # What this process does to the files, for the ones started after it, is not known.
            self.model.foreign_effects = True
            return
        if module == "venv":
            self._venv(module_args)
            return
        if module in HARMLESS_PYTHON_MODULES:
            return
        script = python_script(args)
        if script is not None and module is None:
            path = self._path(script, "python script")
            self._audited_script(path)
            return
        raise Unsupported(
            "python code run at build time"
            + (f" (-m {module})" if module else " (-c)" if "-c" in args else "")
            + " has effects on the files the model does not know"
        )

    def _read(self, path):
        """Text of a file of the model, None when the model does not know it
        (below a mount or another path of unknown content included)."""
        if path is None or self.stage.written(path):
            return None
        return self.model.context.read(self.files.get(path))

    def _audited_script(self, path):
        text = self._read(path)
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

    def _venv(self, options):
        """``python -m venv [--clear] DIR`` (``options`` follow the module):
        --clear empties an existing DIR."""
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
            path = self._path(directory, "venv directory")
            if clear:
                remove_files(self.files, path)

    def _uv(self, args, conditional, env):
        if args[:1] == ["pip"]:
            self._pip(args[1:], conditional, env)
            return
        if args[:1] == ["venv"]:
            # uv venv replaces an existing environment directory.
            targets = [a for a in args[1:] if not a.startswith("-")]
            for target in targets or [".venv"]:
                self._forget(target, record=False)
            return
        raise Unsupported(f"'uv {' '.join(args[:1])}' is not modelled")

    def _other_command(self, words, literal_args=None, env=None, conditional=False):
        """A command the model only accepts when it knows its effect on the files."""
        name = posixpath.basename(words[0])
        args = words[1:]
        if name == "printf" and args and args[0].startswith("-v"):
            # printf -v NAME (or -vNAME) sets a variable.
            variable = args[0][2:] or (args[1] if len(args) > 1 else "")
            self.variables[variable] = UNKNOWN
            return
        if name == "mkdir":
            self._mkdir(args, uncertain=conditional)
            return
        if name == "touch":
            self._touch(args)
            return
        if name in AUDITED_SUBCOMMANDS and (
            not args or args[0] not in AUDITED_SUBCOMMANDS[name]
        ):
            raise Unsupported(f"'{' '.join([name, *args[:1]])}' is not modelled")
        if name in HARMLESS_COMMANDS or name in AUDITED_PROGRAMS:
            return
        if name == "chmod":
            recursive = any(a in ("-R", "--recursive") for a in args)
            paths = literal_args if literal_args is not None else args
            operands = [a for a in paths if a not in CHMOD_OPTIONS][1:]
            for operand in operands:
                path = self._path(operand, "chmod operand")
                # A directory also needs its search permission (a pattern may
                # match one).
                directory = self._is_dir(path) or (
                    bool(GLOB_CHARS.search(path))
                    and any(
                        shell_glob_match(path, d)
                        for f in self.files
                        for d in self_and_parents(posixpath.dirname(f))
                    )
                )
                if not harmless_mode(args, recursive or directory):
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
            names, variables = DOWNLOADER_CONFIGS[name]
            written = (*self.files, *self.stage.replaced)
            # The places the configuration is read from, in the home directory
            # or in /etc, including below a directory a COPY filled.
            places = [
                f"{home}/{config}"
                for home in ("/root", "/etc", self.variables.get("HOME", "/root"))
                for config in names
            ]
            # The environment of the command, prefix assignments and env included.
            if (
                any(posixpath.basename(p) in names for p in written)
                or any(v in self.variables or v in (env or {}) for v in variables)
                or any(self.stage.written(place) for place in places)
            ):
                # A configuration file of the build may add outputs.
                raise Unsupported(f"{name} with a configuration file of the build")
            for output in download_outputs(name, args, self.cwd):
                self._forget(output, created=True)
            return
        if name == "git" and args[:1] == ["clone"]:
            # A clone creates a new directory (git refuses a non-empty one),
            # whose content the model does not know.
            operands = []
            i = 1
            while i < len(args):
                if args[i] == "--separate-git-dir" or args[i].startswith(
                    "--separate-git-dir="
                ):
                    raise Unsupported("git clone --separate-git-dir")
                if args[i] in GIT_CLONE_OPTIONS_WITH_VALUE:
                    i += 2
                    continue
                if not args[i].startswith("-"):
                    operands.append(args[i])
                i += 1
            if not operands:
                raise Unsupported("git clone without a repository")
            target = (
                operands[1]
                if len(operands) > 1
                else posixpath.basename(operands[0].rstrip("/")).removesuffix(".git")
            )
            path = self._path(target, "git clone directory")
            self.stage.unknown_dirs.add(path)
            return
        raise Unsupported(
            f"'{name}' is not a command the model knows the effects of on the image files"
        )

    def _touch(self, args):
        """touch: a file of the model, or a directory, keeps its content; a file
        it creates is empty, a content the model does not know, which a COPY
        --from of its directory carries (an empty program shadows the real one)."""
        operands = []
        create = True
        options = True
        i = 0
        while i < len(args):
            arg = args[i]
            if options and arg == "--":
                options = False
            elif options and arg in TOUCH_OPTIONS_WITH_VALUE:
                i += 1
            elif options and arg.startswith("-") and arg != "-":
                if arg == "--no-create" or re.fullmatch(r"-[acfhm]*c[acfhm]*", arg):
                    create = False
            else:
                operands.append(arg)
            i += 1
        if not create:
            return
        for operand in operands:
            path = self._path(operand, "touched path")
            if GLOB_CHARS.search(path):
                # A pattern touches the files it matches; they keep their content.
                continue
            self._through_link(path)
            if path not in self.files and not self._is_dir(path):
                self.stage.replaced.add(path)

    def _forget(self, candidate, created=False, record=True):
        """``candidate`` (and everything below it) may have been rewritten.

        ``created``: the command writes this file (a download, a log), so a bare
        name is a path even when the model has nothing there. ``record``: the
        path keeps a content the model does not know (not for an environment the
        interpreter creates, whose programs are its own)."""
        if not candidate or candidate.startswith("-") or "\n" in candidate:
            return
        if "$" in candidate or "`" in candidate:
            raise Unsupported(
                f"a command acts on '{candidate}', which uses a variable or a command the build does not define"
            )
        bare = (
            not candidate.startswith(("/", "~", "./", "../")) and "/" not in candidate
        )
        if bare and not GLOB_CHARS.search(candidate):
            if self.cwd is None:
                if created or STAMP in candidate:
                    raise Unsupported(f"'{candidate}' in an unknown working directory")
                return
            path = posixpath.join(self.cwd, candidate)
            # Otherwise a bare word is a file only when the model has it in the
            # working directory.
            if not created and (
                path not in self.files
                and not any(f.startswith(path + "/") for f in self.files)
            ):
                return
        path = self._path(candidate, "named path")
        self._through_link(path)
        if path != "/":
            before = set(self.files)
            remove_files(self.files, path)
            if record:
                # Still there, with a content or mode the model does not know:
                # an executable among them is no longer the file the model read.
                self.stage.replaced.update(before - set(self.files))
                self.stage.replaced.add(path)

    def _executed_script(self, words, env, conditional):
        """A shell script of the image run as a command: it runs here (its
        deletions count, and in a start script its python processes). A python
        script of the image is a python process of a start script. True when the
        command was one of these."""
        path = self.model.find_executable(
            words[0], self.cwd, env, self.files, self.stage.links
        )
        text = self._read(path)
        program = interpreter_of(text, self.model, env, self.files, self.stage)
        if program in SHELLS:
            check_shell_environment(program, env)
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
        """``. file`` runs the file in this shell: its ``cd``, variables and
        deletions count."""
        if not args:
            raise Unsupported(f"'{name}' without a file")
        if "/" not in args[0]:
            # The shell searches PATH for it, not the working directory (bash also
            # falls back to the working directory).
            raise Unsupported(
                f"sourced file '{args[0]}' without a '/', searched on PATH"
            )
        path = self._path(args[0], "sourced file")
        text = self._read(path)
        if text is None:
            # A file the model does not know may do anything to the files.
            raise Unsupported(f"sourced file {path} is not a file of the image model")
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
        nested.exported = self.exported
        nested.allexport = self.allexport
        nested.run(text)
        self.cwd = nested.cwd
        self.allexport = nested.allexport

    def _mkdir(self, args, uncertain=False):
        """The directories mkdir creates: a later COPY puts a file inside them; a
        mode that removes read or search permission hides what they will hold.
        ``uncertain``: the mkdir may not run, so a later ``cd`` into them may fail
        and leave the shell where it was. Without ``-p`` it creates no parent and
        fails when the parent is missing: its directory is certain only below a
        directory of the model."""
        mode = None
        parents = False
        operands = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-m", "--mode"):
                mode = args[i + 1] if i + 1 < len(args) else None
                i += 2
                continue
            if arg.startswith(("--mode=", "-m")):
                mode = arg.split("=", 1)[1] if arg.startswith("--") else arg[2:]
            elif arg == "--":
                operands += args[i + 1 :]
                break
            elif re.fullmatch(r"-[pv]+", arg) or arg in ("--parents", "--verbose"):
                parents = (
                    parents or arg == "--parents" or (arg[1] != "-" and "p" in arg)
                )
            elif arg.startswith("-"):
                raise Unsupported(f"mkdir {arg}")
            else:
                operands.append(arg)
            i += 1
        for operand in operands:
            path = self._path(operand, "mkdir operand")
            sure = not uncertain and (parents or self._is_dir(posixpath.dirname(path)))
            for directory in self_and_parents(path) if parents else [path]:
                if sure:
                    self.stage.dirs.add(directory)
                elif not self._is_dir(directory):
                    self.stage.uncertain_dirs.add(directory)
            if mode is not None and not harmless_mode([mode], True):
                self.stage.replaced.add(path)

    def _unknown_directory(self, why):
        if self.start:
            raise Unsupported(f"working directory changed by {why} in the entry script")
        self.cwd = None

    def _cd(self, args, conditional, in_pipeline, env, after):
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
        # CDPATH of the command: a prefix assignment applies to the builtin too.
        if env.get("CDPATH") and not target.startswith(("/", ".")):
            self._unknown_directory("a relative 'cd' searched in CDPATH")
            return
        target = self._path(target, "'cd' target")
        if not self._is_dir(target):
            # The image may not have it: a failed cd leaves the shell where it was.
            if after != "&&":
                self._unknown_directory(
                    "a 'cd' to a directory the image model does not know"
                )
                return
            # The commands of the && list run there only; after the list the
            # shell may still be where it was.
            self.chain_directory = True
        self.cwd = target

    def _path(self, value, what="path"):
        """Absolute image path of an operand (a ``..`` after a link the build
        created is reported)."""
        return image_path(self._tilde(value), self.cwd, what, self.stage.links)

    def _tilde(self, value):
        if value == "~" or value.startswith("~/"):
            return self.variables.get("HOME", "/root") + value[1:]
        if value.startswith("~"):
            # ~NAME is the home directory of NAME in the account database of the
            # image, ~+ and ~- the current and the previous directory.
            raise Unsupported(
                f"path '{value}' starts with a tilde prefix the image model does not resolve"
            )
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

    def _delete(self, operands, directories=False):
        """The operands leave the model, with the directories among them when
        ``directories`` is set: a later cd into one of them fails."""
        for operand in operands:
            target = self._path(operand, "deleted path")
            self._through_link(target)
            remove_files(self.files, target)
            if directories:
                remove_dirs(self.stage.dirs, target)

    def _move(self, args):
        target_dir, no_target, rest = target_options(args)
        operands = self._operands(rest)
        sources = operands if target_dir else operands[:-1]
        if not sources:
            return
        destination = target_dir if target_dir else operands[-1]
        destination = self._path(destination, "mv destination")
        for path in (
            destination,
            *(self._path(s, "mv source") for s in sources),
        ):
            self._through_link(path)
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
        # The moved files and directories leave their place; where they land is
        # not modelled.
        self._delete(sources, directories=True)

    def _is_dir(self, path):
        prefix = path.rstrip("/") + "/"
        return path in self.stage.dirs or any(f.startswith(prefix) for f in self.files)

    def _link(self, args):
        """``ln``: the link replaces whatever the model had at its path."""
        target_dir, no_target, rest = target_options(args)
        operands = self._operands(rest)
        if not operands:
            return
        symbolic = any(
            re.fullmatch(r"-[a-zA-Z]*s[a-zA-Z]*", a) or a == "--symbolic" for a in rest
        )
        if target_dir:
            link = self._path(target_dir, "link directory")
            targets = operands
        else:
            link = self._path(operands[-1], "link path")
            targets = operands[:-1] or [operands[-1]]
            if no_target or len(operands) == 1 or not self._is_dir(link):
                # The link is this path.
                remove_files(self.files, link)
                self.stage.replaced.add(link)
                self._record_link(link, targets[0], symbolic)
                return
        for target in targets:
            # A link created inside an existing directory takes the target's name.
            name = posixpath.basename(target.rstrip("/"))
            remove_files(self.files, posixpath.join(link, name))
            self.stage.replaced.add(posixpath.join(link, name))
            self._record_link(posixpath.join(link, name), target, symbolic)

    def _record_link(self, link, target, symbolic):
        """What the link at ``link`` stands for: a symbolic link resolves from its
        own directory, a hard link names an existing file (None: not known)."""
        if "$" in target or (
            not symbolic and self.cwd is None and not target.startswith("/")
        ):
            self.stage.links[link] = None
        elif symbolic:
            self.stage.links[link] = posixpath.normpath(
                posixpath.join(posixpath.dirname(link), target)
            )
        else:
            self.stage.links[link] = self._path(target)

    def _through_link(self, path):
        """Report an operation on ``path`` when it goes through a link the build
        created to files of the model: it acts on them under another name. A
        wildcard goes through every link its expansion can reach."""
        for link, target in self.stage.links.items():
            if (
                path != link
                and not path.startswith(link.rstrip("/") + "/")
                and not pattern_reaches(path, link)
            ):
                continue
            if target is None or any(
                f == target or f.startswith(target.rstrip("/") + "/")
                for f in self.files
            ):
                raise Unsupported(
                    f"{path} goes through the link {link} the build created"
                )

    def _find(self, args):
        # Options before the roots: -H, -L and -P (symbolic links), -D, -O.
        while args and re.fullmatch(r"-[HLP]|-O\d*|-D", args[0]):
            if args[0] in ("-H", "-L") and (
                {"-delete", "-exec", "-execdir", "-ok", "-okdir"} & set(args)
            ):
                # Followed links lead to files the model does not place there.
                raise Unsupported(f"find {args[0]} acting on what it finds")
            args = args[2:] if args[0] == "-D" else args[1:]
        if "-follow" in args and {"-delete", "-exec", "-execdir"} & set(args):
            raise Unsupported("find -follow acting on what it finds")
        roots = []
        while args and not args[0].startswith("-") and args[0] not in ("(", "!", ")"):
            roots.append(args[0])
            args = args[1:]
        roots = roots or ["."]
        deletes = "-delete" in args
        for index, arg in enumerate(args):
            if arg.startswith(("-fprint", "-fls")) and index + 1 < len(args):
                # find writes this file.
                self._forget(args[index + 1], created=True)
            if arg not in ("-exec", "-execdir", "-ok", "-okdir"):
                continue
            command = []
            for word in args[index + 1 :]:
                if word in (";", "+"):
                    break
                command.append(word)
            if not command:
                continue
            relative = "/" in command[0] and not command[0].startswith("/")
            if arg in ("-execdir", "-okdir") and relative:
                # Resolved from the directory of each match.
                raise Unsupported(f"find {arg} {command[0]}")
            # find runs the program it finds with its own environment.
            environment = {
                k: v for k, v in self.variables.items() if k in self.exported
            }
            if self.model.shadow(
                command[0], environment, self.files, self.stage, self.cwd
            ):
                raise Unsupported(f"find {arg} {command[0]}: a file the build wrote")
            program = posixpath.basename(command[0])
            if program in SHELLS or program == "xargs":
                raise Unsupported("a shell or xargs started from find")
            explicit = [word for word in command[1:] if word != "{}"]
            # mv is not one of them: what it puts at its destination, a match
            # through {} included, is not followed.
            if program in ("rm", "unlink"):
                if arg in ("-execdir", "-okdir") and any(
                    not operand.startswith("/") for operand in self._operands(explicit)
                ):
                    # Resolved from the directory of each match.
                    raise Unsupported(f"find {arg} {program} with a relative operand")
                # Operands other than the matched path are deleted as well.
                deletes = True
                self._delete(
                    self._operands(explicit),
                    directories=program == "rm" and removes_directories(explicit),
                )
            elif program in ("mkdir", "touch"):
                if any("{}" in word for word in explicit):
                    raise Unsupported(
                        f"find {arg} {program} on a path built from the match"
                    )
                if arg in ("-execdir", "-okdir") and any(
                    not operand.startswith("/") for operand in self._operands(explicit)
                ):
                    # Resolved from the directory of each match.
                    raise Unsupported(f"find {arg} {program} with a relative operand")
                # What it creates is in the model, as when the build runs it.
                if program == "mkdir":
                    self._mkdir(explicit)
                else:
                    self._touch(explicit)
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
        # find evaluates left to right: a test after an action never narrows
        # what the action did (-name a -delete -name b deletes every a).
        acted = False
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
                if arg == "-type" and not acted:
                    kind = args[i + 1]
                elif arg == "-name" and not acted:
                    name = args[i + 1]
                i += 2
                continue
            if arg == "-delete":
                acted = True
                i += 1
                continue
            if arg in ("-exec", "-execdir", "-ok", "-okdir"):
                acted = True
                while i < len(args) and args[i] not in (";", "+"):
                    i += 1
                i += 1
                continue
            understood = False
            break
        for root in roots:
            base = self._path(root, "find root")
            if GLOB_CHARS.search(base):
                raise Unsupported(f"find root '{root}' with a wildcard")
            self._through_link(base)
            # The installed packages are also reached by their native path; the
            # predicates hold as such only when the mapping is exact.
            exact = bool(NATIVE_SITE_PACKAGES.match(base))
            for modelled in modelled_targets(base):
                keep_predicates = understood and (modelled == base or exact)
                self._find_delete(modelled, kind, name, keep_predicates)

    def _find_delete(self, base, kind, name, understood):
        """The files and directories find deletes below ``base`` (-type / -name
        when understood): a later cd into a deleted directory fails."""
        prefix = base.rstrip("/") + "/"
        for path in list(self.stage.dirs):
            if not (path == base or path.startswith(prefix)):
                continue
            if (
                not understood
                or (kind in (None, "d") and name is None)
                or (
                    kind in (None, "d")
                    and any(
                        fnmatch.fnmatchcase(posixpath.basename(d), name)
                        for d in self_and_parents(path)
                        if d == base or d.startswith(prefix)
                    )
                )
            ):
                remove_dirs(self.stage.dirs, path)
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
        script = shell_script(args, self.cwd, self.files, self.model, self.stage)
        if script is None:
            raise Unsupported("a shell reading its commands from its standard input")
        if not self.start and audited(script):
            return
        self._nested(self.files, self.cwd, dict(env), self.start, conditional).run(
            script
        )

    def _pip(self, args, conditional, env):
        """pip: ``install <path>`` records the installed packages; an option that
        writes a file (--report, --log) or into a directory takes it out of the
        model; ``uninstall`` removes installed packages."""
        if not self.start:
            # pip is a python program (uv pip runs the interpreter as well).
            self._check_startup_hooks(env)
        # Global options come before the command.
        while args and args[0].startswith("-"):
            option, sep, attached = args[0].partition("=")
            value = attached if sep else (args[1] if len(args) > 1 else None)
            if option in PIP_WRITE_OPTIONS:
                self._forget(value, created=True)
            elif option == "--python":
                raise Unsupported("pip --python: another interpreter")
            if option in PIP_WRITE_OPTIONS or option in PIP_GLOBAL_OPTIONS_WITH_VALUE:
                args = args[1:] if sep else args[2:]
            else:
                args = args[1:]
        if not args:
            return
        command, args = args[0], args[1:]
        # -e./x, -rx.txt, --editable=./x: the value of the option is attached.
        args = [part for arg in args for part in split_option([arg])]
        if command in PIP_READ_ONLY_COMMANDS or (
            command == "config" and args[:1] in (["list"], ["get"], ["debug"])
        ):
            return
        if command not in ("install", "uninstall"):
            # wheel and download build local projects; config set writes pip.conf.
            raise Unsupported(f"pip {command}: its effect on the files is not modelled")
        self._check_pip_configuration(env)
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
                    # A report or a log is a file pip writes; a relocated
                    # install holds the packages, taken as published.
                    writes = option in PIP_WRITE_OPTIONS
                    self._forget(value, created=writes, record=writes)
                i += 1 if sep else 2
                continue
            if option in ("-e", "--editable"):
                editable = True
                if value:
                    targets.append(value)
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
        if command != "install":
            return
        if self.start:
            raise Unsupported("pip install in the entry script")
        local = [
            *(p for p in (self._local_requirement(t) for t in targets) if p),
            *self._requirement_files(args),
        ]
        for path in local:
            if self.stage.written(path):
                raise Unsupported(f"pip install of {path}, which holds unknown content")
            if path in self.files or PIP_ARCHIVE.search(path):
                # A wheel or a source archive of the repository: its content is
                # not read (a source archive runs its setup.py).
                raise Unsupported(f"pip install of the local archive {path}")
            # Whether pip installs it or not, it runs the packaging code.
            self.model.check_packaging(self.files, path)
        if editable or conditional:
            return
        for path in local:
            if relocated:
                raise Unsupported(
                    "pip install into another directory than site-packages"
                )
            self.model.install_package(self.files, path, self.stage)

    def _check_pip_configuration(self, env):
        """pip also reads options from the environment (PIP_*) and from pip.conf:
        only the reviewed variables are accepted, and no configuration file the
        build wrote."""
        # The environment of the command, prefix assignments and env included.
        for key in sorted({*self.variables, *env}):
            if key.startswith("PIP_") and key not in PIP_REVIEWED_VARIABLES:
                raise Unsupported(f"pip with {key} set")
        written = (*self.files, *self.stage.replaced)
        places = [
            f"{home}/{name}"
            for home in (
                "/etc",
                "/etc/xdg/pip",
                "/root/.pip",
                "/root/.config/pip",
                self.variables.get("HOME", "/root") + "/.config/pip",
            )
            for name in ("pip.conf", "pip.ini")
        ]
        if any(
            posixpath.basename(p) in ("pip.conf", "pip.ini") for p in written
        ) or any(self.stage.written(place) for place in places):
            raise Unsupported("pip with a configuration file of the build")

    def _local_requirement(self, requirement):
        """Image path of a requirement that names a local directory, or None."""
        value = requirement.strip()
        if " @ " in value:
            value = value.split(" @ ", 1)[1].strip()
        value = re.sub(r"\[[^\]]*\]$", "", value)
        if value.startswith("file://"):
            value = value[len("file://") :]
        if "://" in value or not (
            value.startswith((".", "/")) or "/" in value or PIP_ARCHIVE.search(value)
        ):
            return None
        return self._path(value, "pip install path")

    def _requirement_files(self, args, seen=None):
        """Local directories the requirement files of ``args`` (-r, -c) name,
        nested files included."""
        seen = set() if seen is None else seen
        found = []
        for index, arg in enumerate(args):
            option, sep, attached = arg.partition("=")
            if option not in ("-r", "--requirement", "-c", "--constraint"):
                if re.fullmatch(r"-r.+", arg):
                    option, attached, sep = "-r", arg[2:], "attached"
                else:
                    continue
            value = (
                attached
                if sep
                else (args[index + 1] if index + 1 < len(args) else None)
            )
            if not value or "://" in value:
                continue
            path = self._path(value, "requirement file")
            if path in seen:
                continue
            seen.add(path)
            text = self._read(path)
            if text is None:
                raise Unsupported(
                    f"requirement file {path} is not a file of the image model"
                )
            base = posixpath.dirname(path)
            for line in text.splitlines():
                line = line.split(" #", 1)[0].strip()
                if not line or line.startswith("#"):
                    continue
                words = split_option(line.split())
                if (
                    words[0] in ("-r", "--requirement", "-c", "--constraint")
                    and len(words) > 1
                ):
                    nested = (
                        posixpath.join(base, words[1])
                        if not words[1].startswith("/")
                        else words[1]
                    )
                    found += self._requirement_files([words[0], nested], seen)
                    continue
                if words[0] in ("-e", "--editable") and len(words) > 1:
                    words = words[1:]
                if words[0].startswith("-"):
                    continue
                # A relative path is read from the working directory of pip.
                target = words[0] if " @ " not in line else line
                local = self._local_requirement(target)
                if local:
                    found.append(local)
        return found


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
                check_shell_options(shell[1:])
                stage.shell = shell
            elif instruction == "VOLUME":
                paths, shell_form = parse_command(expand(arguments, stage.variables))
                for path in paths.split() if shell_form else paths:
                    stage.volumes.append(image_path(path, stage.workdir, "VOLUME"))
            elif instruction == "ENTRYPOINT":
                stage.entrypoint = parse_command(arguments)
                if not stage.cmd_set:
                    # ENTRYPOINT clears a CMD inherited from the base, not one
                    # this stage declared.
                    stage.cmd = None
            elif instruction == "CMD":
                stage.cmd = parse_command(arguments)
                stage.cmd_set = True
            elif instruction == "HEALTHCHECK":
                self._healthcheck(stage, arguments)
        if stage is None:
            raise Unsupported("no FROM instruction")
        self.final = stage
        if not KNOWN_BASE_IMAGE.match(stage.base or ""):
            raise Unsupported(
                f"base image {stage.base}: its entry point, volumes and ONBUILD triggers are not known"
            )
        self._check_healthcheck(stage)

    @staticmethod
    def _healthcheck(stage, arguments):
        """HEALTHCHECK: the last one of the stage, or of the stage it starts from,
        applies to the image (NONE removes it)."""
        rest = arguments
        while rest.startswith("--"):
            rest = first_word(rest)[1]
        if rest.upper() == "NONE":
            stage.healthcheck = None
            return
        instruction, rest = first_word(rest)
        if instruction.upper() != "CMD":
            raise Unsupported("a HEALTHCHECK without CMD")
        stage.healthcheck = parse_command(rest)

    def _check_healthcheck(self, stage):
        """The health check runs next to the connector, in the final image: it
        must leave its files alone."""
        if stage.healthcheck is None:
            return
        command, shell_form = stage.healthcheck
        files = dict(stage.files)
        variables = {"PATH": DEFAULT_PATH, **stage.env}
        # The probe runs on its own copy of everything a command may change.
        probe = replace(
            stage,
            files=files,
            dirs=set(stage.dirs),
            variables=dict(stage.variables),
            env=dict(stage.env),
            volumes=list(stage.volumes),
            replaced=set(stage.replaced),
            links=dict(stage.links),
            unknown_dirs=set(stage.unknown_dirs),
            uncertain_dirs=set(stage.uncertain_dirs),
        )
        shell = Shell(self, probe, files, stage.workdir, variables, start=False)
        if shell_form:
            # The shell form runs with the SHELL of the image, in its environment.
            if posixpath.basename(stage.shell[0]) not in SHELLS:
                raise Unsupported(f"HEALTHCHECK through the shell {stage.shell[0]}")
            if self.shadow(
                stage.shell[0], variables, stage.files, stage, stage.workdir
            ):
                raise Unsupported(
                    f"HEALTHCHECK through the shell {stage.shell[0]}, a file the build wrote"
                )
            check_shell_environment(stage.shell[0], variables)
            shell.run(command)
        elif command:
            shell.exec_form(command)
        if (
            probe.files,
            probe.dirs,
            probe.replaced,
            probe.links,
            probe.unknown_dirs,
            probe.uncertain_dirs,
        ) != (
            stage.files,
            stage.dirs,
            stage.replaced,
            stage.links,
            stage.unknown_dirs,
            stage.uncertain_dirs,
        ):
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
            stage.base = image
            if not KNOWN_BASE_IMAGE.match(image):
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
            if key in stage.env:
                # An ENV value wins over an ARG of the same name.
                continue
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
            elif not KNOWN_BASE_IMAGE.match(source_stage.base or ""):
                # A stage built on an image whose content is not known: its
                # commands are not the programs the model knows, so even the
                # files the model placed there may have been rewritten.
                entries, opaque = [], True
            else:
                entries, opaque = self._stage_entries(source_stage, sources)
        else:
            entries, opaque = self._context_entries(instruction, sources)
        dest_path = image_path(dest, stage.workdir, "COPY destination")
        many = len(sources) > 1 or any(GLOB_CHARS.search(s) for s in sources)
        dest_is_dir = dest.endswith("/") or dest in (".", "./") or many
        into_dir = dest_is_dir or stage.is_dir(dest_path)

        def linked(target):
            """The link of the build ``target`` is, or lies below."""
            for link in stage.links:
                if target == link or target.startswith(link.rstrip("/") + "/"):
                    return link
            return None

        def through_link(target, link_origin=False):
            # Docker writes through the link: what it replaces lies at the
            # target of the link, which the model does not follow.
            link = linked(target)
            if link is not None and not (target == link and link_origin):
                raise Unsupported(
                    f"{instruction} to {target} goes through the link {link} the build created"
                )

        if opaque:
            through_link(dest_path)
            # Content the model does not know (external image, URL, archive) may
            # replace the destination, or anything below a destination directory.
            remove_files(stage.files, dest_path)
            if not from_values:
                # A URL, a repository or an archive of ADD: any file may land there.
                stage.unknown_dirs.add(dest_path)
        if from_values and source_stage is not None:
            carried = self._carried_writes(source_stage, sources, dest_path, into_dir)
            if carried and keep_parents:
                raise Unsupported("COPY --parents of files a build command wrote")
            # The links of that stage land as links, whose target is not followed here.
            carried_links = self._carried_writes(
                source_stage, sources, dest_path, into_dir, set(source_stage.links)
            )
            for target in carried:
                through_link(target, target in carried_links)
            stage.replaced.update(carried)
            for landed in carried_links:
                stage.links[landed] = None
        origin_image = (
            str(from_values[-1])
            if from_values and source_stage is None
            else (source_stage.base if from_values else None)
        )
        if origin_image is not None and not (
            KNOWN_BASE_IMAGE.match(origin_image) or audited_image(origin_image)
        ):
            # Files of an image whose content is not known: any of them, a
            # wrapper named after a program included, may land there.
            stage.unknown_dirs.add(dest_path)
        if from_values and not into_dir:
            for source in sources:
                path = image_path(source, "/", "COPY --from source")
                # A file of the model, or a directory of the model, whose
                # content keeps its names below the destination.
                known = source_stage is not None and (
                    path in source_stage.files or source_stage.is_dir(path)
                )
                renamed = posixpath.basename(path.rstrip("/")) != posixpath.basename(
                    dest_path
                )
                if renamed and not known:
                    # A file the model does not know, under another name: it is
                    # not the program that name stands for (/bin/sh as python3).
                    stage.replaced.add(dest_path)

        chmod = flags.get("chmod", [])
        unreadable = bool(chmod) and not harmless_mode([str(chmod[-1])])
        # Copied directories get the mode as well: it must keep them searchable.
        unsearchable = bool(chmod) and not harmless_mode([str(chmod[-1])], True)

        def excluded(relative, name):
            # Matched against the path in the source and in the context: never less than Docker excludes.
            return any(rx.match(name) or rx.match(relative) for rx in excludes)

        def place(target, origin, in_directory=False):
            through_link(target, origin[0] == "link")
            through_written = any(
                stage.written(parent)
                for parent in self_and_parents(posixpath.dirname(target))
                if parent != "/"
            )
            if origin[0] == "link" or through_written:
                # A link of the context, or a path below one the build wrote (a
                # link the copy writes through): the destination holds what the
                # model does not know.
                remove_files(stage.files, target)
                stage.replaced.add(target)
                if origin[0] == "link":
                    # Where it points is not modelled: an operation through it is
                    # reported (_through_link).
                    stage.links[target] = None
            elif origin[0] == "stamp" and (
                unreadable or (in_directory and unsearchable)
            ):
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
                regex = glob_regex(normalized, globstar=False)
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
                if instruction == "ADD" and self.context.is_archive(match):
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
    def _carried_writes(source_stage, sources, dest_path, into_dir, regions=None):
        """Where the regions of ``source_stage`` whose content the model does
        not know (what a build command wrote, a directory a clone or a COPY
        filled), or the given ``regions``, land when a COPY --from takes them:
        they stay unknown there."""
        if regions is None:
            regions = {*source_stage.replaced, *source_stage.unknown_dirs}

        def below(path, region):
            return path == region or path.startswith(region.rstrip("/") + "/")

        targets = set()
        for source in sources:
            path = image_path(source, "/", "COPY --from source")
            glob = GLOB_CHARS.search(path)
            if glob:
                # The directory the pattern starts from.
                prefix = path[: glob.start()].rsplit("/", 1)[0] or "/"
                if any(below(r, prefix) or below(prefix, r) for r in regions):
                    targets.add(dest_path)
                continue
            for region in regions:
                if below(path, region):
                    # The source lies in such a region: what lands is unknown,
                    # in the destination or below the destination directory.
                    targets.add(dest_path)
                elif below(region, path):
                    # Inside a copied directory, whose content lands in the
                    # destination.
                    relative = posixpath.relpath(region, path)
                    targets.add(posixpath.normpath(posixpath.join(dest_path, relative)))
        return targets

    @staticmethod
    def _stage_entries(source_stage, sources):
        """Entries of a COPY --from a stage, and whether it may bring files the
        model does not know: only a file of the model is copied for certain (a
        directory or a pattern also takes the files of the base image and the
        ones build commands created, such as ``touch``)."""
        entries = []
        opaque = False
        for source in sources:
            # Docker reads COPY --from sources from the root of the stage, not its WORKDIR.
            path = image_path(source, "/", "COPY --from source")
            if path not in source_stage.files:
                opaque = True
            if GLOB_CHARS.search(path):
                # Docker wildcards: unlike the shell, "*" matches a leading dot.
                regex = glob_regex(path.lstrip("/"), globstar=False)
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
        return entries, opaque

    def _run(self, stage, arguments):
        # A mount puts other content at its target for this RUN only: a bind
        # mount of the context puts its files there, any other mount content
        # the model does not know.
        unknown = set()
        mounted = {}
        hidden = {}
        while arguments.startswith("--"):
            flag, arguments = first_word(arguments)
            if not flag.startswith("--mount="):
                continue
            options = dict(
                item.partition("=")[::2] for item in flag[len("--mount=") :].split(",")
            )
            target = next(
                (
                    options[k]
                    for k in ("target", "dst", "destination")
                    if options.get(k)
                ),
                None,
            )
            if target is None:
                raise Unsupported(f"RUN {flag} without a target")
            target = image_path(target, stage.workdir, "mount target")
            for path in [
                f for f in stage.files if f == target or f.startswith(target + "/")
            ]:
                hidden[path] = stage.files.pop(path)
            members = None
            if options.get("type", "bind") == "bind" and not options.get("from"):
                members = self._context_members(
                    options.get("source") or options.get("src") or "."
                )
            if members is None:
                unknown.add(target)
                continue
            for relative, origin in members:
                mounted[posixpath.normpath(posixpath.join(target, relative))] = origin
        added = unknown - stage.unknown_dirs
        stage.unknown_dirs |= added
        stage.files.update(mounted)
        try:
            self._run_command(stage, arguments)
        finally:
            stage.unknown_dirs -= added
            for path in mounted:
                stage.files.pop(path, None)
            stage.files.update(hidden)

    def _context_members(self, source):
        """(relative path, origin) of the context files a bind mount of ``source``
        shows, or None when it is not a file or directory of the context."""
        source = (
            posixpath.normpath(source.lstrip("/")) if source not in ("", ".") else "."
        )
        if source in self.context.files:
            return [("", self.context.files[source])]
        if source in self.context.dirs:
            prefix = "" if source == "." else source + "/"
            return [
                (rel[len(prefix) :], origin)
                for rel, origin in self.context.files.items()
                if rel.startswith(prefix)
            ]
        return None

    def _run_command(self, stage, arguments):
        command, shell_form = parse_command(arguments)
        shell = Shell(
            self, stage, stage.files, stage.workdir, dict(stage.variables), start=False
        )
        shell.build_step = True
        if shell_form:
            if posixpath.basename(stage.shell[0]) not in SHELLS:
                raise Unsupported(f"RUN through the shell {stage.shell[0]}")
            lookup = {"PATH": DEFAULT_PATH, **stage.variables}
            if self.shadow(stage.shell[0], lookup, stage.files, stage, stage.workdir):
                raise Unsupported(
                    f"RUN through the shell {stage.shell[0]}, a file the build wrote"
                )
            check_shell_environment(stage.shell[0], stage.variables)
            shell.run(command)
        elif command:
            shell.exec_form(command)

    def check_packaging(self, files, install_dir):
        """Code of the repository that pip runs for ``install_dir``, whatever
        package it finds: a setup.py, an in-tree build backend."""
        if posixpath.join(install_dir, "setup.py") in files:
            raise Unsupported("packaging declared in setup.py")
        origin = files.get(posixpath.join(install_dir, "pyproject.toml"))
        text = self.context.read(origin) if origin else None
        if not text:
            return
        try:
            build_system = tomllib.loads(text).get("build-system", {})
        except tomllib.TOMLDecodeError as error:
            raise Unsupported(f"pyproject.toml not readable: {error}") from error
        if build_system.get("backend-path"):
            raise Unsupported(
                f"{install_dir}: an in-tree build backend runs during pip install"
            )
        backend = build_system.get("build-backend")
        if backend is not None and backend not in SETUPTOOLS_BACKENDS:
            # Its file selection and build hooks, which may run code of the
            # repository, are not modelled.
            raise Unsupported(f"{install_dir}: the build backend {backend}")

    def install_package(self, files, install_dir, stage):
        """``pip install <install_dir>``: the packages it puts in site-packages.
        ``stage`` gives the directories the build made, an empty one included."""
        texts = {}
        for name in ("pyproject.toml", "setup.cfg", "setup.py", "MANIFEST.in"):
            origin = files.get(posixpath.join(install_dir, name))
            if origin is not None:
                texts[name] = self.context.read(origin) or ""
        if not texts:
            return
        self.check_packaging(files, install_dir)
        config = None
        # Automatic discovery takes the packages of src/ when the project has
        # that directory (the src layout), even an empty one, and none of the
        # top level. The build context holds no empty directory: git keeps none.
        src_dir = posixpath.join(install_dir, "src")
        src_layout = False
        if self._automatic(texts):
            if stage.written(src_dir) or any(
                region.startswith(src_dir + "/")
                for region in (*stage.replaced, *stage.unknown_dirs)
            ):
                raise Unsupported(
                    f"automatic discovery in {install_dir}, whose src holds what a build command wrote"
                )
            src_layout = src_dir in stage.dirs or any(
                path.startswith(src_dir + "/") for path in files
            )
        roots = (
            ["src"]
            if src_layout
            else ["."] + [r for r in self._roots(texts) if r != "."]
        )
        for root in roots:
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
                if (
                    not src_layout and root not in config.package_roots
                ) or not config.installs(package, has_init):
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

    @staticmethod
    def _automatic(texts):
        try:
            return PackagingConfig(texts).automatic
        except Unsupported:
            return False

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
            external = name in EXTERNAL_PREFIXES or "/" in words[0]
            if external and self.shadow(words[0], env, files, self.final, cwd):
                # A wrapper the build wrote under this name runs instead.
                break
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
        shadow = self.shadow(words[0], env, files, self.final, cwd)
        if shadow is None and PYTHON.match(name):
            return [(self.python_start(words, cwd, env, files), dict(files))]
        if shadow is None and name in SHELLS:
            check_shell_environment(name, env)
            script = shell_script(words[1:], cwd, files, self)
            if script is None:
                raise Unsupported("a shell started without a script")
            return self._script(files, cwd, env, nesting, script)
        path = shadow or self._executable(words[0], cwd, env, files)
        text = self._read(files, path)
        if not text.startswith("#!"):
            raise Unsupported(f"entry point {path} has no interpreter line")
        program = interpreter_of(text, self, env, files, self.final)
        if PYTHON.match(program):
            argv = [program, path, *words[1:]]
            return [(self.python_start(argv, cwd, env, files), dict(files))]
        if program in SHELLS:
            check_shell_environment(program, env)
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
    def find_executable(command, cwd, env, files, links=()):
        """Image path of a command: a path, or a file of the model on PATH."""
        if "/" in command:
            if "$" in command or (cwd is None and not command.startswith("/")):
                return None
            return image_path(command, cwd, links=links)
        for candidate in path_candidates(command, env.get("PATH", DEFAULT_PATH), links):
            if candidate is not None and candidate in files:
                return candidate
        return None

    @staticmethod
    def shadow(command, env, files, stage, cwd):
        """The path a command resolves to (on PATH for a bare name) when the build
        put a file there (a file of the model, or one a command replaced): that
        file runs, not the program its name stands for. None otherwise."""
        if "/" in command:
            if "$" in command or (cwd is None and not command.startswith("/")):
                return None
            path = image_path(command, cwd, links=stage.links)
            return path if path in files or stage.written(path) else None
        value = env.get("PATH", DEFAULT_PATH)
        for directory, candidate in zip(
            value.split(":"), path_candidates(command, value, stage.links)
        ):
            if candidate is None:
                # A relative PATH entry depends on the working directory; one
                # built from an unknown value may be any directory.
                if stage.unknown_dirs or any(
                    posixpath.basename(p) == command for p in (*files, *stage.replaced)
                ):
                    kind = "relative" if not directory.startswith("/") else "unresolved"
                    raise Unsupported(f"'{command}' looked up in a {kind} PATH entry")
                continue
            if candidate in files or stage.written(candidate):
                return candidate
        return None

    def _executable(self, command, cwd, env, files):
        if "/" in command:
            return image_path(command, cwd, "entry point", self.final.links)
        path = self.find_executable(command, cwd, env, files, self.final.links)
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
                        if not ignore_env and env.get("PYTHONSAFEPATH") == UNKNOWN:
                            raise Unsupported(
                                "PYTHONSAFEPATH set to a value the model does not follow"
                            )
                        if not ignore_env and env.get("PYTHONSAFEPATH"):
                            safe_path = True
                        main_dir = self._module_dir(
                            value,
                            cwd,
                            env,
                            files,
                            safe_path,
                            ignore_env,
                            no_site,
                            self.final,
                        )
                        return self._readable(main_dir, cwd)
                    if letter in "WX":
                        if not cluster[position + 1 :]:
                            i += 1
                        break
                i += 1
                continue
            script = image_path(arg, cwd, "python script", self.final.links)
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
        # In the order pycti walks them: the directory of __main__, then the
        # working directory.
        anchors = [d for d in (main_dir, cwd) if d is not None]
        if not anchors:
            raise Unsupported("python started in an unknown working directory")
        return list(dict.fromkeys(anchors))

    @staticmethod
    def _module_dir(
        module, cwd, env, files, safe_path, ignore_env, no_site=False, stage=None
    ):
        parts = module.split(".")
        if not all(part.isidentifier() for part in parts):
            raise Unsupported(f"python -m {module}")
        entries = [] if safe_path else [""]
        if not ignore_env and env.get("PYTHONPATH"):
            entries += env["PYTHONPATH"].split(":")
        bases = []
        for entry in entries:
            if not entry.startswith("/") and cwd is None:
                # The working directory, or a path relative to it.
                raise Unsupported(f"python -m {module} in an unknown working directory")
            bases.append(
                image_path(
                    entry or ".",
                    cwd or "/",
                    "PYTHONPATH entry",
                    stage.links if stage is not None else (),
                )
            )
        if not no_site:
            bases.append(SITE_PACKAGES)
            # The user site-packages, and any other copy of site-packages, come
            # before or beside the installed packages the model keeps.
            elsewhere = sorted(
                f
                for f in files
                if not f.startswith(SITE_PACKAGES + "/")
                and re.search(
                    rf"/(site|dist)-packages/{re.escape(parts[0])}(\.py$|/)", f
                )
            )
            if elsewhere:
                raise Unsupported(
                    f"python -m {module}: a module {parts[0]} also lies in {posixpath.dirname(elsewhere[0])}"
                )
        missing = Unsupported(f"module {module} is not a file of the image model")

        def find(names, search):
            # As the import system: in each entry a package with __init__.py or
            # a module file wins at once; a directory without __init__.py is a
            # namespace portion, used only when no entry has either.
            name, rest = names[0], names[1:]
            portions = []
            for base in search:
                path = posixpath.join(base, name)
                if stage is not None and (
                    stage.written(path)
                    or stage.written(f"{path}.py")
                    or stage.written(f"{path}/__init__.py")
                ):
                    raise Unsupported(
                        f"python -m {module}: {path} holds what a build command wrote"
                    )
                if f"{path}/__init__.py" in files:
                    portions = [path]
                    break
                if f"{path}.py" in files:
                    if rest:
                        raise missing
                    return base
                if any(f.startswith(path + "/") for f in files):
                    portions.append(path)
            if not portions:
                raise missing
            if rest:
                return find(rest, portions)
            for portion in portions:
                if f"{portion}/__main__.py" in files:
                    return portion
            raise missing

        return find(parts, bases)


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


def pycti_version(text):
    """The version pycti takes from an identity file, None when it skips the file
    (not a JSON object, or no usable version)."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("version") or data.get("container_version")
    version = "" if value is None else str(value).strip()
    if version.lower() in VERSION_SENTINELS or version.startswith("$"):
        return None
    return "".join(c for c in version if c.isalnum() or c in "._+-")[:64] or None


def coverage(image, model, anchors, files):
    """Whether a python process reading ``anchors`` takes its identity from a
    stamp the build wrote: pycti keeps the first identity file it reads."""
    stamps = sorted(
        path
        for path, origin in files.items()
        if origin[0] == "stamp" and posixpath.basename(path) == STAMP
    )

    def volume_of(path):
        return next(
            (v for v in model.final.volumes if path.startswith(v.rstrip("/") + "/")),
            None,
        )

    for directory in (d for anchor in anchors for d in ancestors(anchor)):
        for name in IDENTITY_FILES:
            path = posixpath.join(directory, name)
            origin = files.get(path)
            if origin is None and not model.final.written(path):
                continue
            volume = volume_of(path)
            if volume is not None:
                # A mount decides what pycti reads there.
                what = "stamp at" if origin and origin[0] == "stamp" else "pycti reads"
                return Result(
                    image,
                    False,
                    f"{what} {path} is below VOLUME {volume}: a mount at run time hides it",
                )
            if origin is None:
                return Result(
                    image,
                    False,
                    f"pycti reads {path} before any build stamp, and a build step put content the model does not know there",
                )
            if origin[0] == "stamp":
                return Result(image, True, f"stamp at {path}")
            if origin[0] == "link":
                return Result(
                    image,
                    False,
                    f"pycti reads {path} before any build stamp, a link of the build context ({origin[1]})",
                )
            version = pycti_version(model.context.read(origin) or "")
            if version is not None:
                return Result(
                    image,
                    False,
                    f"pycti reads {path} ({origin[1]} of the build context, version '{version}') before any build stamp",
                )
    if any(
        anchor == SITE_PACKAGES or anchor.startswith(SITE_PACKAGES + "/")
        for anchor in anchors
    ):
        # pycti also walks up from the physical site-packages, a path the model
        # does not know (the prefix, a virtual environment, the python version).
        above = [s for s in stamps if NATIVE_SITE_PARENT.match(posixpath.dirname(s))]
        if above:
            return Result(
                image,
                False,
                f"stamp at {above[0]}: pycti reads it only from the site-packages"
                " below it, a path the image model does not know; ship the stamp"
                " in the package",
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
        missing = [
            connector
            for connector in args.connectors
            if not (root / connector / "Dockerfile").is_file()
        ]
        if missing:
            # A path that names no image would report a check that never ran.
            parser.error(f"no Dockerfile in {', '.join(missing)}")
        dirs = [(root / connector).resolve() for connector in args.connectors]
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
