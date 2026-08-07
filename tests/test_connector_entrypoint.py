"""
Test that every connector's launch entrypoint points to a real file.

A connector image builds fine but crashes on startup if the command it runs
(``python <script>`` / ``python -m <module>``) references a file that does not
exist in the image. This is the class of regression reported in #7154
(``CONNECTOR_CMD="connector.py"`` while only ``main.py`` existed).

There are three independent ways a connector declares that command:

1. ``.build.env`` ``CONNECTOR_CMD`` -- consumed by the generic UBI9 image
   (``Dockerfile_ubi9`` / ``build_ubi9.sh``). The UBI9 image always does
   ``COPY src /opt/connector/src`` and runs ``python3.12 ${CONNECTOR_CMD}``
   from ``CONNECTOR_WORKDIR`` (default ``/opt/connector/src``).

2. ``entrypoint.sh`` -- the standard Alpine image's ``ENTRYPOINT``. It does
   ``cd <workdir>`` then ``python[3] <script>`` (or ``-m <module>``).

3. Dockerfile ``CMD`` / ``ENTRYPOINT`` (exec-form) -- for connectors that have
   no ``entrypoint.sh`` and launch python directly from the Dockerfile.

For every connector we resolve each declared command against the layout the
image actually builds -- reverse-mapping the in-container path back to the repo
tree using the Dockerfile ``COPY`` instructions -- and verify the target file
exists. Commands that cannot be resolved statically (e.g. pip
``console_scripts`` entrypoints, ``.`` copies, custom unmappable workdirs) are
skipped rather than guessed, to avoid false failures.
"""

import re
import shlex
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
CONNECTOR_DIRS = [
    REPO_ROOT / "external-import",
    REPO_ROOT / "internal-enrichment",
    REPO_ROOT / "internal-export-file",
    REPO_ROOT / "internal-import-file",
    REPO_ROOT / "stream",
]

# UBI9 image defaults, mirrored from Dockerfile_ubi9. The UBI9 image copies the
# connector's src/ to /opt/connector/src and runs python3.12 ${CONNECTOR_CMD}
# from ${CONNECTOR_WORKDIR}.
UBI9_DEFAULT_CMD = "main.py"
UBI9_DEFAULT_WORKDIR = "/opt/connector/src"
UBI9_SRC_MOUNT = "/opt/connector/src"

_INTERPRETER_RE = re.compile(r"^(?:.*/)?python[0-9.]*$")

# Marker prefixed to a synthetic, non-existent repo path used to report a
# command whose in-container path is covered by no COPY (e.g. a relative command
# with a missing WORKDIR). The path never exists on disk, so it is reported as a
# missing-entrypoint violation.
_UNRESOLVED = "<unresolved> "

# KEY="value" / KEY='value' / KEY=value assignment in a .build.env line.
_ASSIGN_RE = re.compile(
    r'(?P<key>[A-Z_][A-Z0-9_]*)\s*=\s*(?P<value>"[^"]*"|\'[^\']*\'|\S+)'
)


# --------------------------------------------------------------------------- #
# Command tokenizing helpers
# --------------------------------------------------------------------------- #
def _strip_interpreter(tokens: list[str]) -> list[str]:
    """Drop a leading python interpreter token (``python``, ``python3.12``)."""
    if tokens and _INTERPRETER_RE.match(tokens[0]):
        return tokens[1:]
    return tokens


def command_target(tokens: list[str]) -> tuple[str, str] | None:
    """Classify a python command's argument.

    Returns ``("module", <module>)`` for ``-m <module>``, ``("script", <path>)``
    for ``python <script.py>``, or ``None`` when the command is not a resolvable
    python file (e.g. a pip console_scripts entrypoint).
    """
    tokens = _strip_interpreter(list(tokens))
    if not tokens:
        return None
    if tokens[0] == "-m":
        if len(tokens) < 2:
            return None
        return ("module", tokens[1])
    script = tokens[0]
    if not script.endswith(".py"):
        # console_scripts entrypoint or non-python command; not statically
        # resolvable to a file.
        return None
    return ("script", script)


# --------------------------------------------------------------------------- #
# Dockerfile COPY map (container path -> repo path)
# --------------------------------------------------------------------------- #
def _norm_container(path: str) -> str:
    """Normalize a container path (strip trailing slash, keep leading slash)."""
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path


def parse_copy_map(
    dockerfile: str, connector_root: Path
) -> list[tuple[str, str, bool]]:
    """Parse ``COPY`` instructions into ``(dest, repo_src, src_is_dir)`` tuples.

    Only single-source COPYs of paths that exist in the connector are kept.
    Multi-stage (``--from=``) and ``.``/glob copies are ignored (unmappable).
    Relative destinations are resolved against the WORKDIR in effect at that
    point in the Dockerfile. ``dest`` is the normalized in-container
    destination. Destinations that stay unresolved (relative with no known
    WORKDIR, or containing an unexpanded ``${...}``) are dropped.
    """
    entries: list[tuple[str, str, bool]] = []
    workdir = ""
    for instruction, argument in _iter_dockerfile_instructions(dockerfile):
        if instruction == "WORKDIR":
            workdir = argument.strip()
            continue
        if instruction != "COPY":
            continue
        tokens = shlex.split(argument)
        tokens = [t for t in tokens if not t.startswith("--from")]
        flag_stripped = [t for t in tokens if not t.startswith("--")]
        if len(flag_stripped) < 2:
            continue
        *srcs, dest = flag_stripped
        if len(srcs) != 1:
            continue
        src = srcs[0]
        if src == "." or any(ch in src for ch in "*?[]"):
            continue
        src_path = connector_root / src
        if not src_path.exists():
            continue
        resolved_dest = _resolve_dest(dest, workdir)
        if resolved_dest is None:
            continue
        entries.append((resolved_dest, src, src_path.is_dir()))
    return entries


def _resolve_dest(dest: str, workdir: str) -> str | None:
    """Resolve a COPY destination to an absolute container path.

    Relative destinations (``.``, ``./src``) are joined onto WORKDIR. Returns
    None when the destination or workdir contains an unexpanded ``${...}`` build
    arg, or a relative destination has no known WORKDIR.
    """
    if "$" in dest or "$" in workdir:
        return None
    if dest.startswith("/"):
        return _norm_container(dest)
    # Relative destination: needs an absolute WORKDIR to anchor it.
    if not workdir.startswith("/"):
        return None
    if dest in (".", "./"):
        return _norm_container(workdir)
    dest = dest[2:] if dest.startswith("./") else dest
    return _norm_container(f"{workdir.rstrip('/')}/{dest}")


def container_to_repo(
    container_path: str, copy_map: list[tuple[str, str, bool]]
) -> Path | None:
    """Reverse-map an absolute in-container file path to a repo-relative path.

    Later COPY instructions win (they overwrite earlier layers). Returns None
    when no COPY covers the path.
    """
    container_path = _norm_container(container_path)
    match: Path | None = None
    for dest, repo_src, is_dir in copy_map:
        if is_dir:
            # Docker copies the *contents* of a source dir into dest.
            if container_path == dest:
                # The dir itself, not a file.
                continue
            prefix = dest + "/"
            if container_path.startswith(prefix):
                rel = container_path[len(prefix) :]
                match = Path(repo_src) / rel
        else:
            # File source. dest may be the file path, or a directory into which
            # the file is placed under its basename.
            base = Path(repo_src).name
            if container_path == dest or container_path == f"{dest}/{base}":
                match = Path(repo_src)
    return match


def _copy_layout_is_static(dockerfile: str) -> bool:
    """Return True when every ``COPY`` maps statically to a known destination.

    Returns False when any ``COPY`` is ambiguous for reverse-mapping -- multi-
    stage (``--from``), current-dir/glob sources (``.``, ``*``), multiple
    sources, or unexpanded build args. In those cases a container path may be
    uncovered simply because we could not model a ``COPY``, so an unmapped path
    must not be treated as a violation (avoids false positives).
    """
    for instruction, argument in _iter_dockerfile_instructions(dockerfile):
        if instruction != "COPY":
            continue
        try:
            tokens = shlex.split(argument)
        except ValueError:
            return False
        if any(t.startswith("--from") for t in tokens):
            return False
        flag_stripped = [t for t in tokens if not t.startswith("--")]
        if len(flag_stripped) < 2:
            continue
        *srcs, dest = flag_stripped
        if len(srcs) != 1:
            return False
        src = srcs[0]
        if src == "." or any(ch in src for ch in "*?[]"):
            return False
        if "$" in src or "$" in dest:
            return False
    return True


def _is_unresolvable_command(
    target: tuple[str, str], workdir: str, dockerfile: str
) -> bool:
    """Decide whether an unmapped command is a genuine startup-crash violation.

    A python command whose in-container path is covered by no ``COPY`` cannot
    find its file at runtime. Two shapes are flagged:

    - A *relative* command (e.g. ``python main.py`` / ``-m pkg``): the classic
      missing/incorrect ``WORKDIR`` crash. Requires a statically-known
      ``WORKDIR`` (no unexpanded build arg).
    - An *absolute* command (e.g. ``python /opt/main.py``): the file is expected
      at a fixed container path that no ``COPY`` produces.

    In both cases the ``COPY`` layout must be fully static (no ``.``/glob/
    ``--from``/build-arg copies) so an unmapped path is a genuine violation and
    not merely a layout we could not model; otherwise skip to avoid false
    positives.
    """
    _kind, value = target
    if not value.startswith("/") and "$" in workdir:
        # Relative command with an unexpanded build-arg WORKDIR -- cannot decide.
        return False
    return _copy_layout_is_static(dockerfile)


def _resolve_in_container(target: tuple[str, str], workdir: str) -> str | None:
    """Turn a (kind, value) command target + workdir into a container file path."""
    kind, value = target
    workdir = _norm_container(workdir)
    if kind == "script":
        if value.startswith("/"):
            return _norm_container(value)
        return f"{workdir}/{value}"
    # module form: package -> <workdir>/<pkg>/__main__.py, module -> <pkg>.py
    rel = value.replace(".", "/")
    return f"{workdir}/{rel}/__main__.py"


# --------------------------------------------------------------------------- #
# UBI9 resolver (fixed layout from Dockerfile_ubi9)
# --------------------------------------------------------------------------- #
def resolve_ubi9(connector_cmd: str, workdir: str) -> Path | None:
    """Resolve a UBI9 ``CONNECTOR_CMD`` to a repo-relative path under ``src/``.

    The UBI9 image copies the connector's ``src/`` to ``/opt/connector/src``.
    """
    target = command_target(shlex.split(connector_cmd))
    if target is None:
        return None
    container_path = _resolve_in_container(target, workdir)
    if container_path is None:
        return None
    container_path = _norm_container(container_path)
    prefix = UBI9_SRC_MOUNT + "/"
    if container_path == UBI9_SRC_MOUNT:
        return None
    if container_path.startswith(prefix):
        return Path("src") / container_path[len(prefix) :]
    # Command references a path outside the copied src mount -> not resolvable.
    return None


# --------------------------------------------------------------------------- #
# Entrypoint source parsers
# --------------------------------------------------------------------------- #
def parse_entrypoint_sh(content: str) -> tuple[list[str], str] | None:
    """Extract (command_tokens, workdir) from an entrypoint.sh.

    Tracks the last ``cd <dir>`` as the workdir and the last ``python...``
    invocation (optionally prefixed with ``exec``) as the command.
    """
    workdir = ""
    command: list[str] | None = None
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if not tokens:
            continue
        if tokens[0] == "cd" and len(tokens) >= 2:
            workdir = tokens[1]
            continue
        run = tokens[1:] if tokens[0] == "exec" else tokens
        if run and _INTERPRETER_RE.match(run[0]):
            command = run
    if command is None:
        return None
    return command, workdir


def _iter_dockerfile_instructions(dockerfile: str):
    """Yield (instruction, argument_string) for each Dockerfile line."""
    for raw in dockerfile.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        instruction = parts[0].upper()
        argument = parts[1] if len(parts) > 1 else ""
        yield instruction, argument


def dockerfile_workdir(dockerfile: str) -> str:
    """Return the last WORKDIR declared in a Dockerfile (or "")."""
    workdir = ""
    for instruction, argument in _iter_dockerfile_instructions(dockerfile):
        if instruction == "WORKDIR":
            workdir = argument.strip()
    return workdir


def parse_dockerfile_command(dockerfile: str) -> tuple[list[str], str] | None:
    """Extract (command_tokens, workdir) from a Dockerfile's CMD/ENTRYPOINT.

    Uses the last python-launching CMD or ENTRYPOINT and the last WORKDIR.
    HEALTHCHECK lines are ignored because their instruction token is
    ``HEALTHCHECK`` (its embedded CMD is not at line start).
    """
    workdir = ""
    command: list[str] | None = None
    for instruction, argument in _iter_dockerfile_instructions(dockerfile):
        if instruction == "WORKDIR":
            workdir = argument.strip()
            continue
        if instruction not in ("CMD", "ENTRYPOINT"):
            continue
        arg = argument.strip()
        if arg.startswith("["):
            # exec form JSON array
            inner = arg[1:].rstrip("]")
            tokens = [t.strip().strip("\"'") for t in inner.split(",") if t.strip()]
        else:
            # shell form
            try:
                tokens = shlex.split(arg)
            except ValueError:
                continue
        if not tokens:
            continue
        # Ignore entrypoints that just delegate to a shell script (e.g.
        # /entrypoint.sh) -- those are handled via parse_entrypoint_sh.
        if tokens[0].endswith(".sh") or tokens[0] == "/entrypoint.sh":
            continue
        if _INTERPRETER_RE.match(tokens[0]) or (tokens[0].endswith(".py")):
            command = tokens
    if command is None:
        return None
    return command, workdir


# --------------------------------------------------------------------------- #
# Per-connector entrypoint source assembly
# --------------------------------------------------------------------------- #
def parse_build_env(content: str) -> dict[str, str]:
    """Parse a .build.env file into a dict of build args."""
    result: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for match in _ASSIGN_RE.finditer(line):
            value = match.group("value")
            if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
                value = value[1:-1]
            result[match.group("key")] = value
    return result


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def iter_connectors():
    """Yield connector root directories across all connector type dirs."""
    for connector_dir in CONNECTOR_DIRS:
        if not connector_dir.exists():
            continue
        for connector in sorted(connector_dir.iterdir()):
            if connector.is_dir() and (connector / "Dockerfile").is_file():
                yield connector


def resolve_connector_sources(connector: Path) -> list[tuple[str, str, Path]]:
    """Return resolvable (source_label, command, repo_relative_target) tuples.

    Collects the UBI9 command (.build.env) and the standard command
    (entrypoint.sh, else Dockerfile CMD). Unresolvable commands are omitted.
    """
    sources: list[tuple[str, str, Path]] = []

    # 1. UBI9 (.build.env) -- fixed src -> /opt/connector/src layout.
    build_env_path = connector / ".build.env"
    if build_env_path.is_file():
        build_env = parse_build_env(_read(build_env_path))
        cmd = build_env.get("CONNECTOR_CMD", UBI9_DEFAULT_CMD)
        workdir = build_env.get("CONNECTOR_WORKDIR", UBI9_DEFAULT_WORKDIR)
        target = resolve_ubi9(cmd, workdir)
        if target is not None:
            sources.append((".build.env", cmd, target))

    # 2. Standard image -- entrypoint.sh preferred, else Dockerfile CMD.
    dockerfile_path = connector / "Dockerfile"
    copy_map = parse_copy_map(_read(dockerfile_path), connector)

    entrypoint_path = connector / "entrypoint.sh"
    parsed: tuple[list[str], str] | None = None
    label = ""
    if entrypoint_path.is_file():
        parsed = parse_entrypoint_sh(_read(entrypoint_path))
        label = "entrypoint.sh"
        if parsed is not None and not parsed[1]:
            # entrypoint.sh has no `cd`; inherit the Dockerfile WORKDIR.
            parsed = (parsed[0], dockerfile_workdir(_read(dockerfile_path)))
    if parsed is None:
        parsed = parse_dockerfile_command(_read(dockerfile_path))
        label = "Dockerfile"

    if parsed is not None:
        tokens, workdir = parsed
        target = command_target(tokens)
        if target is not None:
            container_path = _resolve_in_container(target, workdir)
            if container_path is not None:
                repo_target = container_to_repo(container_path, copy_map)
                if repo_target is not None:
                    sources.append((label, " ".join(tokens), repo_target))
                elif _is_unresolvable_command(target, workdir, _read(dockerfile_path)):
                    # In-container path is covered by no COPY -- the file will be
                    # absent at runtime (missing/incorrect WORKDIR for a relative
                    # command, or an absolute path no COPY produces). Builds fine
                    # but crashes on startup. Report via a path that cannot exist.
                    sources.append(
                        (
                            label,
                            " ".join(tokens),
                            Path(
                                f"{_UNRESOLVED}{container_path} "
                                f"(no COPY maps it -- check WORKDIR/COPY)"
                            ),
                        )
                    )

    return sources


@pytest.fixture(scope="session")
def entrypoint_violations() -> list[tuple[str, str, str, str]]:
    """Collect (connector, source, command, target) for missing entrypoints."""
    violations: list[tuple[str, str, str, str]] = []
    for connector in iter_connectors():
        for source, command, repo_target in resolve_connector_sources(connector):
            if not (connector / repo_target).is_file():
                violations.append(
                    (
                        str(connector.relative_to(REPO_ROOT)),
                        source,
                        command,
                        str(repo_target),
                    )
                )
    return violations


def test_connector_entrypoint_exists(entrypoint_violations):
    """Verify every connector's launch command resolves to an existing file.

    Prevents images that build successfully but crash on startup because the
    entrypoint points to a non-existent file (regression class of #7154).
    """
    if not entrypoint_violations:
        return

    messages = [
        f"  {connector} [{source}] '{command}' -> missing '{target}'"
        for connector, source, command, target in entrypoint_violations
    ]
    report = "\n".join(messages)
    pytest.fail(
        f"Found {len(entrypoint_violations)} connector entrypoint(s) that do "
        f"not exist:\n{report}\n\n"
        f"Fix: update the connector's entrypoint (.build.env CONNECTOR_CMD, "
        f"entrypoint.sh, or Dockerfile CMD/ENTRYPOINT) to reference a real file."
    )
