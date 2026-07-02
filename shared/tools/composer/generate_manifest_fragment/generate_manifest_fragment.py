# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "jsonschema==4.26.0",
# ]
# ///
"""
Generate a connector *manifest fragment* for XTM Hub delivery.

The fragment follows `connector_manifest_schema.json` (bundled alongside this
script) and is derived from a connector's existing
`__metadata__/connector_manifest.json` and
`__metadata__/connector_config_schema.json`, without modifying either file.

The existing `connector_manifest.json` is kept as-is for backward compatibility
during the release decoupling rollout; this fragment is the new, forward-looking
format published as a release artifact (until the XTM Hub endpoint exists).

Usage:
    python generate_manifest_fragment.py \
        --connector-dir external-import/mitre \
        --version 7.260630.0 \
        --output /tmp/mitre_manifest_fragment.json

Field mapping (existing manifest -> fragment):
    slug              -> id, slug
    logo (file path)  -> logo (base64 data URL)
    support_version   -> min_version (">=" and whitespace stripped)
    <release version> -> version
    container_image   -> image_name
    container_type    -> image_type
    playbook_supported, max_confidence_level -> additional_properties
    connector_config_schema.json -> config_schema (embedded)
Constant fields:
    platform = "OpenCTI", integration_type = "connector"
"""

import argparse
import base64
import json
import os
import re
import sys
import traceback
from pathlib import Path

import jsonschema

CONNECTOR_METADATA_DIRECTORY = "__metadata__"
CONNECTOR_MANIFEST_FILENAME = "connector_manifest.json"
CONNECTOR_CONFIG_SCHEMA_FILENAME = "connector_config_schema.json"

PLATFORM = "OpenCTI"
INTEGRATION_TYPE = "connector"

# Maximum length allowed by the schema for `short_description`.
SHORT_DESCRIPTION_MAX_LENGTH = 200

# Default logo used when a connector does not ship its own.
DEFAULT_LOGO_PATH = (
    Path(__file__).parent.parent
    / "generate_global_manifest"
    / "connector_default_logo.png"
)

MIME_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
}


def find_logo_file(metadata_dir: Path) -> Path:
    """Return the connector's logo path, or the default logo if none is found."""
    if metadata_dir.is_dir():
        for file in os.listdir(metadata_dir):
            if file.startswith("logo."):
                return metadata_dir / file
    print(f"⚠️  No logo found in {metadata_dir}, using the default logo.")
    return DEFAULT_LOGO_PATH


def encode_logo_to_base64(logo_path: Path) -> str:
    """Read a logo file and encode it as a base64 data URL."""
    with open(logo_path, "rb") as logo_file:
        logo_data = logo_file.read()
    mime_type = MIME_TYPES.get(logo_path.suffix.lower(), "image/png")
    encoded_logo = base64.b64encode(logo_data).decode("utf-8")
    return f"data:{mime_type};base64,{encoded_logo}"


def parse_min_version(support_version: str | None) -> str:
    """Convert a `support_version` constraint (e.g. ">= 6.8.0") to a bare version."""
    if not support_version:
        return ""
    match = re.search(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", support_version)
    return match.group() if match else ""


def normalize_slug(slug: str) -> str:
    """Normalize a slug to the URL-friendly form required by the schema.

    Directory names may contain underscores (e.g. "intel471_v2"); the fragment
    id/slug must match `^[a-z0-9]+(?:-[a-z0-9]+)*$`, so underscores become hyphens.
    """
    return slug.lower().replace("_", "-")


def truncate_short_description(text: str) -> str:
    """Truncate `short_description` to the schema's maximum length, adding an ellipsis."""
    if len(text) <= SHORT_DESCRIPTION_MAX_LENGTH:
        return text
    return text[: SHORT_DESCRIPTION_MAX_LENGTH - 3].rstrip() + "..."


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def build_fragment(connector_dir: Path, version: str) -> dict:
    """Build the manifest fragment for a single connector."""
    metadata_dir = connector_dir / CONNECTOR_METADATA_DIRECTORY
    manifest_path = metadata_dir / CONNECTOR_MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    manifest = load_json(manifest_path)

    slug = normalize_slug(manifest["slug"])
    logo = encode_logo_to_base64(find_logo_file(metadata_dir))

    config_schema_path = metadata_dir / CONNECTOR_CONFIG_SCHEMA_FILENAME
    config_schema = (
        load_json(config_schema_path) if config_schema_path.is_file() else {}
    )

    fragment = {
        "id": slug,
        "title": manifest["title"],
        "slug": slug,
        "description": manifest["description"],
        "short_description": truncate_short_description(manifest["short_description"]),
        "logo": logo,
        "use_cases": manifest["use_cases"],
        "verified": manifest.get("verified"),
        "last_verified_date": manifest.get("last_verified_date"),
        "subscription_link": manifest.get("subscription_link") or "",
        "source_code": manifest["source_code"],
        "manager_supported": manifest["manager_supported"],
        "min_version": parse_min_version(manifest.get("support_version")),
        "version": version,
        "image_name": manifest["container_image"],
        "image_type": manifest["container_type"],
        "platform": PLATFORM,
        "integration_type": INTEGRATION_TYPE,
        "additional_properties": {
            "playbook_supported": manifest.get("playbook_supported", False),
            "max_confidence_level": manifest.get("max_confidence_level", 50),
        },
        "config_schema": config_schema,
    }
    return fragment


def validate_fragment(fragment: dict, schema_path: Path) -> None:
    """Validate the fragment against the manifest schema."""
    schema = load_json(schema_path)
    jsonschema.validate(instance=fragment, schema=schema)
    print("✅ Fragment validated against schema.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a connector manifest fragment for XTM Hub delivery."
    )
    parser.add_argument(
        "--connector-dir",
        required=True,
        help="Path to the connector directory (e.g. external-import/mitre).",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Release version to embed in the fragment (e.g. 7.260630.0).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path where the generated fragment JSON will be written.",
    )
    parser.add_argument(
        "--schema",
        default=None,
        help="Path to connector_manifest_schema.json for optional validation. "
        "Defaults to the schema bundled alongside this script.",
    )
    args = parser.parse_args()

    connector_dir = Path(args.connector_dir)
    fragment = build_fragment(connector_dir, args.version)

    schema_path = (
        Path(args.schema)
        if args.schema
        else Path(__file__).parent / "connector_manifest_schema.json"
    )
    if schema_path.is_file():
        validate_fragment(fragment, schema_path)
    else:
        print(f"ℹ️  Schema not found at {schema_path} — skipping validation.")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(json.dumps(fragment, indent=2))

    print(f"✅ Manifest fragment written to {output_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
