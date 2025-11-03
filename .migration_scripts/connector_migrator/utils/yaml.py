import os
from pathlib import Path

import yaml  # if not found run `pip install pyyaml`

from .path import find_file_path


def parse_config_yml_sample(connector_path: Path) -> dict | None:
    config_yml_sample_path = find_file_path(connector_path, "config.yml.sample")
    if not config_yml_sample_path:
        return None

    try:
        config_yml: dict = yaml.safe_load(config_yml_sample_path.read_text("utf-8"))
        return config_yml
    except yaml.YAMLError as e:
        raise RuntimeError("Invalid 'config.yml.sample' content") from e


def parse_docker_compose_yml(connector_path: Path) -> dict | None:
    docker_compose_path = find_file_path(connector_path, "docker-compose.yml")
    if not docker_compose_path:
        return None

    try:
        docker_compose: dict = yaml.safe_load(docker_compose_path.read_text("utf-8"))
        return docker_compose
    except yaml.YAMLError as e:
        raise RuntimeError("Invalid 'docker-compose.yml' content") from e


def get_custom_env_var_prefix(connector_path: Path) -> str | None:
    docker_compose = parse_docker_compose_yml(connector_path)
    if not docker_compose:
        return None

    docker_compose_services = docker_compose.get("services") or {}
    docker_compose_connector_service = next(
        (
            docker_compose_services[service]
            for service in docker_compose_services.keys()
            if service.startswith("connector-")
        ),
        {},
    )
    docker_compose_connector_environment = (
        docker_compose_connector_service.get("environment") or []
    )

    custom_env_vars = [
        docker_env_var.split("=")[0]
        for docker_env_var in docker_compose_connector_environment
        if not docker_env_var.startswith(("OPENCTI_", "CONNECTOR_"))
    ]
    custom_prefix = os.path.commonprefix(custom_env_vars)
    if custom_prefix:
        return custom_prefix.rstrip("_").lower() or None
