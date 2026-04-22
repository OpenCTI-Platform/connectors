import ast
from pathlib import Path

from connector_linter.models import ConnectorContext

# ---------------------------------------------------------------------------
# Source reading
# ---------------------------------------------------------------------------


def read_all_python_sources(ctx: ConnectorContext) -> dict[Path, str]:
    """Read all Python source files from the connector's src/ directory."""
    sources: dict[Path, str] = {}
    # Convention: all connector Python code lives under <connector>/src/
    src_dir = ctx.path / "src"
    if not src_dir.exists():
        return sources
    for py_file in src_dir.rglob("*.py"):
        # Key by relative path (from connector root) for portable reporting
        rel_path = py_file.relative_to(ctx.path)
        try:
            # errors="replace" avoids UnicodeDecodeError on malformed files
            sources[rel_path] = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # Skip unreadable files (permissions, broken symlinks, etc.)
            continue
    return sources


# ---------------------------------------------------------------------------
# AST helpers — structural analysis of Python source
# ---------------------------------------------------------------------------


def parse_sources(sources: dict[Path, str]) -> dict[Path, ast.Module]:
    """Parse all source files into AST modules.

    Files that fail to parse (syntax errors) are silently skipped.
    """
    trees: dict[Path, ast.Module] = {}
    for file_path, content in sources.items():
        try:
            trees[file_path] = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            # Silently skip files with syntax errors — they can't be analyzed
            # structurally, but other checks (regex-based) may still find issues.
            continue
    return trees
