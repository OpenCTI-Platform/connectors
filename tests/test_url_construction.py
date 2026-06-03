"""
Test that connector URL variables are properly stripped to avoid double slashes.

requests >= 2.34.0 no longer normalizes double slashes in URL paths.
All connectors that build URLs from config variables must call .rstrip("/")
on the base URL at assignment time.

This test:
1. Scans all connector source files for URL variable assignments from config
2. Verifies that .rstrip("/") (or equivalent) is applied
3. Checks that URL construction patterns won't produce double slashes
"""

import ast
import re
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

# Broad pattern: any self attribute whose name ends with "url" (case-insensitive).
# This catches self.base_url, self.api_url, self.endpoint_url, self.target_url, etc.
URL_VAR_PATTERN = re.compile(r"(self\.\w*url)\s*=", re.IGNORECASE)

# Pattern that indicates the URL is protected (rstrip, strip, endswith check, conditional trim)
PROTECTED_PATTERNS = [
    r'\.rstrip\s*\(\s*["\']/?["\']\s*\)',
    r'\.strip\s*\(\s*["\']/?["\']\s*\)',
    r'\[-1\]\s*==\s*["\']/',
    r'\.endswith\s*\(\s*["\']/',
    r"if.*\.endswith.*\"/\"",
]


def find_connector_python_files():
    """Find all Python source files in connector src/ directories."""
    files = []
    for connector_dir in CONNECTOR_DIRS:
        if not connector_dir.exists():
            continue
        for connector in sorted(connector_dir.iterdir()):
            src_dir = connector / "src"
            if not src_dir.exists():
                continue
            for py_file in src_dir.rglob("*.py"):
                if "__pycache__" in str(py_file) or "venv" in str(py_file):
                    continue
                files.append(py_file)
    return files


def find_connector_file_groups() -> dict[Path, list[Path]]:
    """Group Python source files by their connector src/ directory."""
    groups: dict[Path, list[Path]] = {}
    for connector_dir in CONNECTOR_DIRS:
        if not connector_dir.exists():
            continue
        for connector in sorted(connector_dir.iterdir()):
            src_dir = connector / "src"
            if not src_dir.exists():
                continue
            py_files = [
                f
                for f in src_dir.rglob("*.py")
                if "__pycache__" not in str(f) and "venv" not in str(f)
            ]
            if py_files:
                groups[src_dir] = py_files
    return groups


def _get_non_docstring_lines(source: str) -> set[int]:
    """Return the set of line numbers that are NOT inside docstrings (AST-based)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # If the file can't be parsed, treat all lines as code (fall back to text scan)
        return set(range(1, source.count("\n") + 2))

    docstring_lines: set[int] = set()

    for node in ast.walk(tree):
        # Docstrings are Expr nodes containing a Constant(str) as first body stmt
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                for ln in range(node.value.lineno, node.value.end_lineno + 1):
                    docstring_lines.add(ln)

    all_lines = set(range(1, source.count("\n") + 2))
    return all_lines - docstring_lines


def get_url_assignments(file_path: Path) -> list[tuple[int, str, str]]:
    """
    Find lines where a URL variable is assigned from config/param (not hardcoded).

    Uses AST to exclude docstrings, then regex to find assignments.
    Returns list of (line_number, variable_name, full_line).
    """
    results = []
    try:
        content = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return results

    code_lines = _get_non_docstring_lines(content)
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        # Skip lines inside docstrings
        if i not in code_lines:
            continue

        stripped = line.strip()

        # Skip comments
        if stripped.startswith("#"):
            continue

        # Match self.*url = ... patterns (broad, catches any URL-like attribute)
        match = URL_VAR_PATTERN.search(line)
        if not match:
            continue

        var_name = match.group(1)

        # Skip if it's a hardcoded string (no config variable involvement)
        # Hardcoded = direct string literal like self.url = "https://..."
        if re.search(r'=\s*["\']https?://', line):
            continue

        results.append((i, var_name, line))

    return results


def is_assignment_protected(file_path: Path, line_num: int, var_name: str) -> bool:
    """
    Check if a URL assignment has .rstrip("/") or equivalent protection.

    Handles:
    - Direct protection: self.url = x.rstrip("/")
    - Intermediate variable: _base = x.rstrip("/"); self.url = f"{_base}/..."
    - Post-assignment guard: self.url = x; if isinstance(self.url, str): self.url = self.url.rstrip("/")
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return True  # can't check, assume ok

    lines = source.splitlines()

    def _has_protection(text: str) -> bool:
        return any(re.search(p, text) for p in PROTECTED_PATTERNS)

    # Try AST-based extraction: find the assignment node at this line
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and node.lineno == line_num:
                stmt_lines = lines[node.lineno - 1 : node.end_lineno]
                assignment_text = "\n".join(stmt_lines)
                if _has_protection(assignment_text):
                    return True

                # Check if the right-hand side of the assignment uses a local
                # variable that was rstrip'd in the preceding 3 lines
                # (intermediate variable pattern)
                start = max(0, node.lineno - 4)
                context = "\n".join(lines[start : node.lineno - 1])
                if _has_protection(context):
                    return True

                # Check following lines for post-assignment isinstance guard
                # Pattern: if isinstance(self.var, str): self.var = self.var.rstrip("/")
                end = min(node.end_lineno + 3, len(lines))
                following = "\n".join(lines[node.end_lineno : end])
                if _has_protection(following) and var_name in following:
                    return True

                return False
    except SyntaxError:
        pass

    # Fallback: text-based extraction for files that can't be parsed
    start = line_num - 1
    end = min(start + 10, len(lines))

    assignment_text = ""
    base_indent = len(lines[start]) - len(lines[start].lstrip())
    for i in range(start, end):
        assignment_text += lines[i] + "\n"
        if i > start:
            current_indent = (
                len(lines[i]) - len(lines[i].lstrip()) if lines[i].strip() else 999
            )
            if current_indent <= base_indent and not lines[i].strip().startswith(")"):
                break

    if _has_protection(assignment_text):
        return True

    # Check preceding lines for intermediate variable pattern
    context_start = max(0, start - 3)
    context = "\n".join(lines[context_start:start])
    return _has_protection(context)


def is_usage_protected(file_path: Path, usage_line_num: int, var_name: str) -> bool:
    """
    Check if a URL usage is protected by a conditional check on the variable.

    Handles patterns like:
    - if self.URL[-1] == "/": URL = f"{self.URL}{EP}" else: URL = f"{self.URL}/{EP}"
    - target = self.url if self.url.endswith("/") else self.url + "/"
    """
    try:
        source = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return False

    lines = source.splitlines()
    short_name = var_name.replace("self.", "")

    # Check a window of 5 lines before and after the usage for conditional checks
    start = max(0, usage_line_num - 6)
    end = min(len(lines), usage_line_num + 3)
    context = "\n".join(lines[start:end])

    # Patterns that indicate runtime handling of trailing slash
    runtime_patterns = [
        rf"self\.{re.escape(short_name)}\s*\[\s*-1\s*\]\s*==\s*[\"']/",
        rf"self\.{re.escape(short_name)}\.endswith\s*\(\s*[\"']/",
        rf"self\.{re.escape(short_name)}\.rstrip\s*\(\s*[\"']/?[\"']\s*\)",
    ]

    return any(re.search(p, context) for p in runtime_patterns)


def get_url_usages_with_slash(file_path: Path, var_name: str) -> list[tuple[int, str]]:
    """
    Find lines where the URL variable is used in URL construction with a leading slash,
    excluding usages that are already protected by conditional checks.

    Returns list of (line_number, line_content).
    """
    results = []
    try:
        content = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return results

    short_name = var_name.replace("self.", "")

    for i, line in enumerate(content.splitlines(), start=1):
        matched = False
        # f-string pattern: f"{self.xxx_url}/..." or f'{self.xxx_url}/...'
        if re.search(rf'f["\'].*\{{self\.{re.escape(short_name)}\}}/', line):
            matched = True
        # Concatenation pattern: self.xxx_url + "/..." or self.xxx_url + '/...'
        elif re.search(rf"""self\.{re.escape(short_name)}\s*\+\s*['"]\/""", line):
            matched = True

        if matched and not is_usage_protected(file_path, i, var_name):
            results.append((i, line.strip()))

    return results


def get_cross_file_usages_with_slash(
    sibling_files: list[Path], var_name: str
) -> list[tuple[int, str, Path]]:
    """
    Find usages of a URL variable across sibling files in the same connector.

    Catches patterns like self.config.xxx_url + "/..." or f"{self.config.xxx_url}/..."
    where the attribute is accessed via a nested config object.

    Returns list of (line_number, line_content, file_path).
    """
    results = []
    short_name = var_name.replace("self.", "")

    for sibling in sibling_files:
        try:
            content = sibling.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        for i, line in enumerate(content.splitlines(), start=1):
            matched = False
            # f-string: f"{self.config.xxx_url}/..." or f"{self.xxx.xxx_url}/..."
            if re.search(
                rf"""f['"].*\{{self\.\w+\.{re.escape(short_name)}\}}/""", line
            ):
                matched = True
            # Concatenation: self.config.xxx_url + "/..." or + '/...'
            elif re.search(
                rf"""self\.\w+\.{re.escape(short_name)}\s*\+\s*['"]\/""", line
            ):
                matched = True

            if matched:
                results.append((i, line.strip(), sibling))

    return results


# Collect all unprotected URL assignments across the codebase
def collect_unprotected_assignments():
    """Scan all connectors and collect unprotected URL assignments that are used with /."""
    violations = []
    connector_groups = find_connector_file_groups()

    for src_dir, py_files in connector_groups.items():
        for py_file in py_files:
            assignments = get_url_assignments(py_file)
            for line_num, var_name, line in assignments:
                if is_assignment_protected(py_file, line_num, var_name):
                    continue

                # Check same-file usages
                usages = get_url_usages_with_slash(py_file, var_name)

                # Check cross-file usages (via self.config.xxx_url or similar)
                sibling_files = [f for f in py_files if f != py_file]
                cross_usages = get_cross_file_usages_with_slash(sibling_files, var_name)
                for ln, code, xfile in cross_usages:
                    rel_xfile = xfile.relative_to(REPO_ROOT)
                    usages.append((ln, f"[{rel_xfile}] {code}"))

                if usages:
                    rel_path = py_file.relative_to(REPO_ROOT)
                    violations.append(
                        (str(rel_path), line_num, var_name, line.strip(), usages)
                    )
    return violations


@pytest.fixture(scope="session")
def url_violations():
    """Lazily collect violations at test time, not at import/collection time."""
    return collect_unprotected_assignments()


def test_no_unprotected_url_assignments(url_violations):
    """
    Verify that all URL variables assigned from config have .rstrip("/") protection.

    This prevents double slashes in URLs when requests >= 2.34.0 is used,
    which no longer normalizes // in URL paths.
    """
    if not url_violations:
        return

    messages = []
    for file_path, line_num, var_name, assignment, usages in url_violations:
        usage_lines = ", ".join(f"L{ln}" for ln, _ in usages[:3])
        messages.append(
            f"  {file_path}:{line_num} - {var_name} assigned without .rstrip('/') "
            f"(used at {usage_lines})"
        )
    violation_report = "\n".join(messages)
    pytest.fail(
        f"Found {len(url_violations)} URL variable(s) without .rstrip('/') protection:\n"
        f"{violation_report}\n\n"
        f"Fix: Add .rstrip('/') to the assignment, e.g.:\n"
        f"  self.base_url = str(config.url).rstrip('/')"
    )


def collect_unprotected_helper_url_usages():
    """
    Find usages of self.helper.opencti_url (from pycti) in URL construction
    without inline .rstrip("/") protection.

    pycti does not strip the trailing slash from opencti_url, so connectors
    must protect at the usage site.
    """
    violations = []
    helper_url_pattern = re.compile(r"self[._]+helper\.opencti_url")

    for py_file in find_connector_python_files():
        try:
            content = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        for i, line in enumerate(content.splitlines(), start=1):
            if not helper_url_pattern.search(line):
                continue

            # Check if this line uses the URL with a slash (f-string or concat)
            has_slash_usage = (
                re.search(r"self[._]+helper\.opencti_url\}['\"]?\s*/", line)
                or re.search(r"self[._]+helper\.opencti_url\}\s*/", line)
                or re.search(r"self[._]+helper\.opencti_url\s*\+\s*['\"]\/", line)
                or re.search(r"\{self[._]+helper\.opencti_url\}/", line)
            )
            if not has_slash_usage:
                continue

            # Check if .rstrip is applied inline
            if "rstrip" in line:
                continue

            rel_path = py_file.relative_to(REPO_ROOT)
            violations.append((str(rel_path), i, line.strip()))

    return violations


@pytest.fixture(scope="session")
def helper_url_violations():
    """Collect unprotected self.helper.opencti_url usages."""
    return collect_unprotected_helper_url_usages()


def test_no_unprotected_helper_opencti_url(helper_url_violations):
    """
    Verify that self.helper.opencti_url usages in URL construction
    include .rstrip("/") since pycti does not strip it.
    """
    if not helper_url_violations:
        return

    messages = []
    for file_path, line_num, code in helper_url_violations:
        messages.append(f"  {file_path}:{line_num} - {code}")
    violation_report = "\n".join(messages)
    pytest.fail(
        f"Found {len(helper_url_violations)} unprotected self.helper.opencti_url usage(s):\n"
        f"{violation_report}\n\n"
        f"Fix: Add .rstrip('/') inline, e.g.:\n"
        f"  f\"{{self.helper.opencti_url.rstrip('/')}}/storage/get/{{file_id}}\""
    )


def _resolve_constant_value(source: str, const_name: str) -> str | None:
    """Resolve a module-level constant's string value from source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == const_name:
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        return node.value.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == const_name:
                if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, str
                ):
                    return node.value.value
    return None


def _is_config_attr_protected_in_connector(
    connector_files: list[Path], attr_name: str
) -> bool:
    """
    Check if a config URL attribute was already rstrip'd at assignment time
    somewhere in the connector source files.

    attr_name is the last part of the dotted access, e.g. "api_base_url"
    from "self.config.api_base_url".
    """
    for f in connector_files:
        try:
            content = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            if attr_name not in line:
                continue
            # Check this line and the next few lines for rstrip (multiline assignments)
            window = "\n".join(lines[idx : idx + 6])
            if attr_name in window and "rstrip" in window:
                return True
    return False


def collect_unprotected_config_url_concatenations():
    """
    Find f-string or concatenation patterns where a config URL attribute
    (self.config.xxx_url or self.xxx.xxx_url) is joined with a constant or
    literal that starts with '/', without .rstrip("/") protection.

    This catches cases like:
        url = f"{self.config.api_url}{ENDPOINT}"  # ENDPOINT = "/api/v1/..."
        url = f"{self.config.api_url}/endpoint"
    """
    violations = []
    connector_groups = find_connector_file_groups()

    # Pattern: {self.config.xxx_url} or {self.xxx.xxx_url} in f-string,
    # followed by a variable (constant) in another f-string placeholder: {url}{CONST}
    config_url_in_fstring = re.compile(
        r"""\{(self\.(\w+)\.(\w*url))\}\{(\w+)\}""", re.IGNORECASE
    )
    # Pattern: {self.config.xxx_url}/ directly
    config_url_slash_fstring = re.compile(
        r"""\{(self\.(\w+)\.(\w*url))\}/""", re.IGNORECASE
    )
    # Concatenation: self.config.xxx_url + CONSTANT or + "/..."
    config_url_concat = re.compile(
        r"""(self\.(\w+)\.(\w*url))\s*\+\s*(\w+|['"]/)""", re.IGNORECASE
    )

    for src_dir, py_files in connector_groups.items():
        for py_file in py_files:
            try:
                content = py_file.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

            code_lines = _get_non_docstring_lines(content)
            lines = content.splitlines()

            for i, line in enumerate(lines, start=1):
                if i not in code_lines:
                    continue
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                # Skip if line already has rstrip protection
                if "rstrip" in line:
                    continue

                matched_url_attr = None
                attr_name = None

                # Case 1: f-string with config URL followed by constant name
                m = config_url_in_fstring.search(line)
                if m:
                    url_attr = m.group(1)
                    attr_name = m.group(3)
                    const_name = m.group(4)
                    const_val = _resolve_constant_value(content, const_name)
                    if const_val and const_val.startswith("/"):
                        matched_url_attr = url_attr

                # Case 2: f-string with config URL followed directly by /
                if not matched_url_attr:
                    m = config_url_slash_fstring.search(line)
                    if m:
                        matched_url_attr = m.group(1)
                        attr_name = m.group(3)

                # Case 3: concatenation with config URL + constant or + "/..."
                if not matched_url_attr:
                    m = config_url_concat.search(line)
                    if m:
                        url_attr = m.group(1)
                        attr_name = m.group(3)
                        rhs = m.group(4)
                        if rhs.startswith(("'", '"')):
                            # Direct string literal starting with /
                            matched_url_attr = url_attr
                        else:
                            # It's a variable name - resolve it
                            const_val = _resolve_constant_value(content, rhs)
                            if const_val and const_val.startswith("/"):
                                matched_url_attr = url_attr

                if matched_url_attr and attr_name:
                    # Check if this attribute was already rstrip'd at assignment
                    if _is_config_attr_protected_in_connector(py_files, attr_name):
                        continue
                    rel_path = py_file.relative_to(REPO_ROOT)
                    violations.append((str(rel_path), i, stripped))

    return violations


@pytest.fixture(scope="session")
def config_url_concat_violations():
    """Collect unprotected config URL concatenations with leading-slash constants."""
    return collect_unprotected_config_url_concatenations()


def test_no_unprotected_config_url_concatenations(config_url_concat_violations):
    """
    Verify that config URL attributes (HttpUrl fields) used in f-strings
    or concatenations with leading-slash paths include .rstrip("/") protection.

    Pydantic HttpUrl adds a trailing slash on str() conversion, so
    f"{self.config.api_url}/endpoint" produces a double slash.
    """
    if not config_url_concat_violations:
        return

    messages = []
    for file_path, line_num, code in config_url_concat_violations:
        messages.append(f"  {file_path}:{line_num} - {code}")
    violation_report = "\n".join(messages)
    pytest.fail(
        f"Found {len(config_url_concat_violations)} config URL concatenation(s) without .rstrip('/') protection:\n"
        f"{violation_report}\n\n"
        f"Fix: Add .rstrip('/') inline, e.g.:\n"
        f"  url = f\"{{str(self.config.api_url).rstrip('/')}}/endpoint\""
    )
