"""
Test that ``templates/create_connector_dir.sh`` copies every template file.

Shell globs skip dotfiles, so a ``cp "$TEMPLATE_DIR/"*`` copy silently drops the
template's ``.dockerignore``: the generated connector then sends ``.env`` and
``config.yml`` (local credentials) into its Docker build context.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
TEMPLATE_TYPES = sorted(
    path.name for path in TEMPLATES_DIR.iterdir() if (path / "Dockerfile").is_file()
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("bash") is None,
    reason="The generation script needs bash and GNU sed",
)


@pytest.mark.parametrize("template_type", TEMPLATE_TYPES)
def test_generated_connector_keeps_the_template_dotfiles(tmp_path, template_type):
    # Given a copy of the templates, so that the generation stays in tmp_path
    templates = tmp_path / "templates"
    shutil.copytree(TEMPLATES_DIR, templates)
    dotfiles = sorted(
        path.name
        for path in (templates / template_type).iterdir()
        if path.name.startswith(".")
    )

    # When a connector is generated from the template
    subprocess.run(
        [
            "bash",
            "create_connector_dir.sh",
            "-t",
            template_type,
            "-n",
            "demo-connector",
        ],
        cwd=templates,
        check=True,
        capture_output=True,
    )

    # Then the template dotfiles are part of the generated connector
    generated = tmp_path / template_type / "demo-connector"
    assert ".dockerignore" in dotfiles
    for name in dotfiles:
        assert (generated / name).is_file(), f"{name} was not copied"


@pytest.mark.parametrize("template_type", TEMPLATE_TYPES)
def test_generated_connector_with_a_numeric_name_segment_compiles(
    tmp_path, template_type
):
    # Given a copy of the templates and a name with a numeric segment, which the
    # script accepts
    templates = tmp_path / "templates"
    shutil.copytree(TEMPLATES_DIR, templates)

    # When a connector is generated from the template
    subprocess.run(
        ["bash", "create_connector_dir.sh", "-t", template_type, "-n", "demo-2"],
        cwd=templates,
        check=True,
        capture_output=True,
    )

    # Then its class names are camel-cased and every Python file compiles
    generated = tmp_path / template_type / "demo-2"
    sources = {
        path: path.read_text(encoding="utf-8") for path in generated.rglob("*.py")
    }
    assert sources
    assert any("Demo2Connector" in text for text in sources.values())
    for path, text in sources.items():
        assert "Demo-2" not in text, path
        compile(text, str(path), "exec")
