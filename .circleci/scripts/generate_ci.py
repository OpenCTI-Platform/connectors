import os

import requests
import yaml
from jinja2 import Template

# Define the top-level directories
TOP_LEVEL_DIRS = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]

CI_DIR = ".circleci"
TEMPLATE_DIR = f"{CI_DIR}/templates"
TEMPLATE_PATH = f"{TEMPLATE_DIR}/dynamic.yml.j2"
VARS_PATH = f"{CI_DIR}/vars.yml"

REPOSITORY = "opencti"


def get_latest_pycti_release() -> str:
    url = "https://api.github.com/repos/OpenCTI-Platform/client-python/releases/latest"
    headers = {"Accept": "application/vnd.github.v3+json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data.get("tag_name")  # Return the tag name of the latest release
    else:
        print("Failed to fetch the release info")
        exit(1)


def get_dirs() -> dir:
    # Collect subdirectories for each top-level directory
    dirs = {}
    for top_dir in TOP_LEVEL_DIRS:
        if os.path.exists(top_dir):
            dirs[top_dir] = [
                sub_dir
                for sub_dir in os.listdir(top_dir)
                if os.path.isdir(os.path.join(top_dir, sub_dir))
            ]
    return dirs


# Load the Jinja template
def get_parameters() -> dict:
    with open(f"{CI_DIR}/vars.yml", "r") as yaml_file:
        return yaml.safe_load(yaml_file)


def get_template() -> Template:
    with open(TEMPLATE_PATH, "r") as template_file:
        return Template(template_file.read())


def get_pycti() -> dict:
    pycti = {"version": os.getenv("CIRCLE_TAG")}
    if pycti["version"]:
        pycti["replace"] = False
    else:
        pycti["version"] = get_latest_pycti_release()
        pycti["replace"] = True
    return pycti


def get_tags() -> list[str]:
    data = []
    tags = os.getenv("BUILD_TAGS")
    if tags:
        data.extend(tags.split(","))

    circle_tag = os.getenv("CIRCLE_TAG")
    if circle_tag:
        data.append(circle_tag)
    if len(data) == 0:
        print("[ERROR]: At least 1 tag is required")
        exit(1)
    return data


# Write the generated config to a CircleCI configuration file
def write_config(template):
    output_path = "dynamic.yml"
    with open(output_path, "w") as file:
        file.write(template)
    print(f"Generated CircleCI config at {output_path}")


def main():
    template = get_template()
    config = template.render(
        dirs=get_dirs(),
        param=get_parameters(),
        pycti=get_pycti(),
        tags=get_tags(),
        repo=REPOSITORY,
    )
    write_config(config)


if __name__ == "__main__":
    main()