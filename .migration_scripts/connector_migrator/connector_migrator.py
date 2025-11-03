import json
import os
import re
import shutil
from pathlib import Path
import subprocess

import yaml  # if not found run `pip install pyyaml`
from connector_migrator import templates_adapters
from connector_migrator.utils.ast import get_connector_class_file_path, remove_dead_code
from connector_migrator_ai_assistant import ConnectorMigratorAIAssistant

CONNECTOR_IGNORED_SUBDIRECTORIES = [
    "__pycache__",
    "venv",
]


class ConnectorMigrator:
    def __init__(self, connector_path: Path | str):
        self.connector_path = Path(connector_path)

        self.ai_assistant = ConnectorMigratorAIAssistant(self.connector_path)

        self.entrypoint_path = self._get_entrypoint_path()
        self._backup_directory()

    def _find_file_path(self, file_name: str) -> Path | None:
        """Equivalent of first result of `find <connector_path> -type f -name <file_name>` in Bash."""

        for rootdir, dirs, files in os.walk(self.connector_path):
            # Modify dirs in place to skip ignored ones
            dirs[:] = [
                dir
                for dir in dirs
                if not (dir.startswith(".") or dir in CONNECTOR_IGNORED_SUBDIRECTORIES)
            ]

            # Look for file in allowed dirs
            for file in files:
                if file == file_name:
                    return Path(rootdir) / file

    def _get_entrypoint_path(self) -> Path:
        """Return `entrypoint.sh` path."""

        # Handle packaged app
        main_path = self._find_file_path("__main__.py")
        if main_path:
            return main_path

        # If not found, try parsing entrypoint.sh
        entrypoint_sh_path = self._find_file_path("entrypoint.sh")
        if entrypoint_sh_path:
            lines = entrypoint_sh_path.read_text("utf-8").splitlines()
            for line in lines:
                if line.startswith(("python ", "python3 ", "/venv/bin/python ")):
                    _, file_name = line.split(" ")
                    file_path = self._find_file_path(file_name)
                    if file_path:
                        return file_path

        # If not found, try parsing Dockerfile
        dockerfile_path = self._find_file_path("Dockerfile")
        if dockerfile_path:
            lines = dockerfile_path.read_text("utf-8").splitlines()
            for line in reversed(lines):
                if line.startswith(("CMD ", "ENTRYPOINT ")):
                    args_string = line.replace("CMD ", "").replace("ENTRYPOINT ", "")
                    args = json.loads(args_string)
                    file_name = os.path.basename(args[-1])
                    file_path = self._find_file_path(file_name)
                    if file_path:
                        return file_path

        raise RuntimeError("Connector main module not found")

    def _backup_directory(self):
        shutil.copytree(
            self.connector_path,
            Path(self.connector_path.as_posix() + "_bak"),
            dirs_exist_ok=True,
        )

    def _rename_docker_compose(self):
        docker_compose_path = self._find_file_path("docker-compose.yaml")
        if docker_compose_path:
            correct_path = (
                docker_compose_path.as_posix()
                .replace(".yaml", ".yml")
                .rstrip(".sample")
            )
            os.replace(docker_compose_path, correct_path)

    def _rename_config_yaml_sample(self):
        config_yaml_sample_path = self._find_file_path("config.yaml.sample")
        if config_yaml_sample_path:
            correct_path = config_yaml_sample_path.as_posix().replace(
                ".yaml.sample", ".yml.sample"
            )
            os.replace(config_yaml_sample_path, correct_path)

    def _update_requirements_txt(self):
        requirements_txt_path = self._find_file_path("requirements.txt")
        if not requirements_txt_path:
            return

        lines = requirements_txt_path.read_text("utf-8").rstrip().splitlines()

        pydantic_line = [line for line in lines if "pydantic" in line]
        if not pydantic_line:
            lines.append("pydantic >=2.8.2, <3")

        connectors_sdk_line = [line for line in lines if "connectors-sdk" in line]
        if not connectors_sdk_line:
            lines.append(
                "connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk"
            )

        if not pydantic_line or not connectors_sdk_line:
            requirements_txt_content = "\n".join(lines) + "\n"
            requirements_txt_path.write_text(requirements_txt_content, encoding="utf-8")

    def _update_docker_compose(self):
        docker_compose_path = self._find_file_path("docker-compose.yml")
        if not docker_compose_path:
            return
            # raise RuntimeError("File 'docker-compose.yml' not found")

        lines = docker_compose_path.read_text("utf-8").splitlines()

        # Uncomment env vars so they can be parsed by yaml lib later
        uncommented_lines = []
        for line in lines:
            if line.lstrip().startswith("#-"):
                uncommented_line = line.replace("#", "", 1)
                if not uncommented_line.lstrip().startswith("- "):
                    uncommented_line = uncommented_line.replace("-", "- ")
                uncommented_lines.append(uncommented_line)
            else:
                uncommented_lines.append(line)

        lines = uncommented_lines
        lines = [line for line in lines if "CONNECTOR_TYPE=" not in line]

        docker_compose_content = "\n".join(lines) + "\n"
        docker_compose_path.write_text(docker_compose_content, encoding="utf-8")

    def _update_config_yaml_sample(self):
        config_yaml_sample_path = self._find_file_path("config.yml.sample")
        if not config_yaml_sample_path:
            return

        lines = config_yaml_sample_path.read_text("utf-8").splitlines()

        # Uncomment env vars so they can be parsed by yaml lib later
        uncommented_lines = []
        for line in lines:
            if re.match("^#[a-z]", line.lstrip()):
                uncommented_line = line.replace("#", "", 1)
                uncommented_lines.append(uncommented_line)
            else:
                uncommented_lines.append(line)

        # TODO: remove connector.type ?

        config_yaml_sample_content = "\n".join(uncommented_lines) + "\n"
        config_yaml_sample_path.write_text(config_yaml_sample_content, encoding="utf-8")

    def _add_dot_env_sample(self):
        config_yml_sample_path = self._find_file_path("config.yml.sample")
        dot_env_sample_path = self._find_file_path(".env.sample")
        if config_yml_sample_path or dot_env_sample_path:
            return

        docker_compose_path = self._find_file_path("docker-compose.yml")
        if not docker_compose_path:
            raise RuntimeError("File 'docker-compose.yml' not found")

        env_vars = []
        try:
            docker_compose: dict = yaml.safe_load(
                docker_compose_path.read_text("utf-8")
            )
        except yaml.YAMLError as e:
            raise RuntimeError("Invalid 'docker-compose.yml' content") from e

        docker_compose_services = docker_compose.get("services") or {}
        docker_compose_connector_service = next(
            (
                docker_compose_services[service]
                for service in docker_compose_services.keys()
                if service.startswith("connector-")
            ),
            {},
        )
        env_vars = docker_compose_connector_service.get("environment")
        if isinstance(env_vars, dict):  # normalize to expected syntax
            env_vars = [
                f"{env_var_name}={env_vars[env_var_name]}" for env_var_name in env_vars
            ]

        if env_vars:
            dot_env_path = self.connector_path / ".env.sample"
            dot_env_content = "\n".join(env_vars) + "\n"
            dot_env_path.write_text(dot_env_content, encoding="utf-8")

    def _add_connector_connector_tmp(self):
        if not os.path.exists(self.connector_path / "src"):
            raise RuntimeError("Directory 'src' not found.")

        src_subdirectory_path = self.entrypoint_path.parent
        if os.path.exists(self.connector_path / "src" / "connector"):
            src_subdirectory_path = self.connector_path / "src" / "connector"
        else:
            src_subdirectories = [
                entry
                for entry in os.scandir(self.connector_path / "src")
                if entry.is_dir()
                and not entry.name.startswith(".")
                and not entry.name in CONNECTOR_IGNORED_SUBDIRECTORIES
            ]

            if len(src_subdirectories) == 0:
                src_subdirectory_path = self.connector_path / "src" / "connector"
                src_subdirectory_path.mkdir(parents=True, exist_ok=True)
            if len(src_subdirectories) == 1:
                src_subdirectory_path = (
                    self.connector_path / "src" / src_subdirectories[0]
                )

        python_files = []
        for _, _, files in os.walk(self.connector_path / "src"):
            for file in files:
                if file.endswith(".py"):
                    python_files.append(file)

        if len(python_files) == 1:
            connector_tmp_path = src_subdirectory_path / "connector.py.tmp"
            connector_tmp_path.write_text(
                self.entrypoint_path.read_text("utf-8"), encoding="utf-8"
            )
        else:
            connector_class_path = get_connector_class_file_path(
                self.connector_path, self.entrypoint_path
            )
            if connector_class_path:
                if connector_class_path.as_posix() == self.entrypoint_path.as_posix():
                    connector_tmp_path = src_subdirectory_path / "connector.py.tmp"
                    connector_tmp_path.write_text(
                        self.entrypoint_path.read_text("utf-8"),
                        encoding="utf-8",
                    )
                elif (
                    connector_class_path.parent.as_posix()
                    == self.entrypoint_path.parent.as_posix()
                ):
                    connector_tmp_path = src_subdirectory_path / "connector.py.tmp"
                    connector_class_path.replace(connector_tmp_path)
                else:
                    connector_tmp_path = (
                        connector_class_path.parent / "connector.py.tmp"
                    )
                    connector_class_path.replace(connector_tmp_path)

        if self.entrypoint_path.name == "__main__.py":
            return

        # Rename entry point file to avoid name collision
        self.entrypoint_path = self.entrypoint_path.rename(
            self.entrypoint_path.parent / "main.py"
        )

    def _add_connector_settings_tmp(self):
        settings_tmp_path = self._find_file_path("settings.py.tmp")
        if settings_tmp_path:
            return

        connector_tmp = self._find_file_path("connector.py.tmp")
        if not connector_tmp:
            raise RuntimeError("File 'connector.py.tmp' not found")

        settings_tmp_content = templates_adapters.src_connector_settings.get_content(
            self.connector_path
        )

        settings_tmp_dir_path = connector_tmp.parent
        settings_tmp_path = settings_tmp_dir_path / "settings.py.tmp"
        settings_tmp_path.write_text(settings_tmp_content, encoding="utf-8")

    def _add_connector_common_tmp(self):
        common_tmp_path = self._find_file_path("common.py.tmp")
        if common_tmp_path:
            return

        settings_tmp_path = self._find_file_path("settings.py.tmp")
        connector_tmp_path = self._find_file_path("connector.py.tmp")
        if not (settings_tmp_path and connector_tmp_path):
            raise RuntimeError("File 'connector.py.tmp' or 'settings.py.tmp' not found")

        common_tmp_parent_path = Path(
            os.path.commonpath(
                [
                    settings_tmp_path,
                    connector_tmp_path,
                ]
            )
        )

        init_path = common_tmp_parent_path / "__init__.py"
        common_tmp_path = common_tmp_parent_path / "common.py.tmp"
        if os.path.exists(init_path):
            init_content = init_path.read_text("utf-8")
            # Copy __init__.py if it declares classes (should declare only __all__ var)
            if "class " in init_content:
                common_tmp_path.write_text(init_content, encoding="utf-8")

    def _add_connector_init_tmp(self):
        init_tmp_path = self._find_file_path("__init__.py.tmp")
        if init_tmp_path:
            return

        settings_tmp_path = self._find_file_path("settings.py.tmp")
        connector_tmp_path = self._find_file_path("connector.py.tmp")
        if not (settings_tmp_path and connector_tmp_path):
            raise RuntimeError("File 'connector.py.tmp' or 'settings.py.tmp' not found")

        # TODO: to fix -> should rely on connector.py.tmp parent only
        init_tmp_parent_path = Path(
            os.path.commonpath(
                [
                    settings_tmp_path,
                    connector_tmp_path,
                ]
            )
        )
        init_path = init_tmp_parent_path / "__init__.py"

        init_tmp_content = templates_adapters.src_connector_init.get_content(
            self.connector_path, self.entrypoint_path, init_path
        )

        init_tmp_path = Path(init_path.as_posix() + ".tmp")
        init_tmp_path.write_text(init_tmp_content, encoding="utf-8")

    def _add_main_tmp(self):
        main_tmp_path = self._find_file_path("main.py.tmp") or self._find_file_path(
            "__main__.py.tmp"
        )
        if main_tmp_path:
            return

        init_tmp_path = self._find_file_path("__init__.py.tmp")
        if not init_tmp_path:
            raise RuntimeError("File '__init__.py.tmp' not found")

        main_tmp_content = templates_adapters.src_main.get_content(
            self.connector_path, init_tmp_path, self.entrypoint_path
        )

        if self.entrypoint_path.name == "__main__.py":
            main_tmp_path = self.entrypoint_path.parent / "__main__.py.tmp"
        else:
            main_tmp_path = self.entrypoint_path.parent / "main.py.tmp"
        main_tmp_path.write_text(main_tmp_content, encoding="utf-8")

    def _add_init(self):
        # Create src/__init__.py only if the connector is developped as a module
        main_tmp_path = self._find_file_path("__main__.py.tmp")
        if not main_tmp_path:
            return

        # Get src/connector/__init__.py.tmp
        init_tmp_path = self._find_file_path("__init__.py.tmp")
        if not init_tmp_path:
            raise RuntimeError("File '__init__.py.tmp' not found")

        src_init_content = templates_adapters.src_init.get_content(
            self.connector_path, init_tmp_path
        )

        src_init_path = self.connector_path / "src" / "__init__.py"
        src_init_path.write_text(src_init_content, encoding="utf-8")

    def _add_test_requirement_text(self):
        test_requirements_txt_path = self._find_file_path("test-requirements.txt")
        if test_requirements_txt_path:
            return

        tests_directory_path = self.connector_path / "tests"

        test_requirements_txt_content = ""
        requirements_txt_path = self._find_file_path("requirements.txt")
        if requirements_txt_path:
            requirements_txt_relative_path = os.path.relpath(
                requirements_txt_path, tests_directory_path
            )
            test_requirements_txt_content = (
                f"-r {requirements_txt_relative_path.replace(os.sep, "/")}"
            )
        test_requirements_txt_content += "\npytest==8.4.2"
        test_requirements_txt_content += "\n"

        test_requirements_txt_path = tests_directory_path / "test-requirements.txt"
        tests_directory_path.mkdir(parents=True, exist_ok=True)
        test_requirements_txt_path.write_text(
            test_requirements_txt_content, encoding="utf-8"
        )

    def _add_test_conftest(self):
        conftest_path = self._find_file_path("conftest.py")
        if conftest_path:
            return

        test_requirements_txt_path = self._find_file_path("test-requirements.txt")
        if not test_requirements_txt_path:
            raise RuntimeError("File 'test-requirements.txt' not found")

        tests_directory_path = test_requirements_txt_path.parent
        tests_conftest_content = templates_adapters.tests_conftest.get_content(
            self.connector_path, tests_directory_path
        )

        tests_conftest_path = tests_directory_path / "conftest.py"
        tests_conftest_path.write_text(tests_conftest_content, encoding="utf-8")

    def _add_test_main(self):
        test_requirements_txt_path = self._find_file_path("test-requirements.txt")
        if not test_requirements_txt_path:
            raise RuntimeError("File 'test-requirements.txt' not found")

        init_tmp_path = self._find_file_path("__init__.py.tmp")
        if not init_tmp_path:
            raise RuntimeError("File '__init__.py.tmp' not found")

        test_main_content = templates_adapters.tests_test_main.get_content(
            self.connector_path, self.entrypoint_path, init_tmp_path
        )

        tests_directory_path = test_requirements_txt_path.parent
        test_main_path = tests_directory_path / "test_main.py"
        test_main_path.write_text(test_main_content, encoding="utf-8")

    def _add_tests_settings(self):
        test_requirements_txt_path = self._find_file_path("test-requirements.txt")
        if not test_requirements_txt_path:
            raise RuntimeError("File 'test-requirements.txt' not found")

        init_tmp_path = self._find_file_path("__init__.py.tmp")
        settings_tmp_path = self._find_file_path("settings.py.tmp")
        if not (init_tmp_path and settings_tmp_path):
            raise RuntimeError("File '__init__.py.tmp' or 'settings.py.tmp' not found")

        test_settings_content = templates_adapters.tests_test_settings.get_content(
            self.connector_path, self.entrypoint_path, init_tmp_path, settings_tmp_path
        )

        tests_directory_path = test_requirements_txt_path.parent
        tests_connector_directory_path = tests_directory_path / "tests_connector"
        tests_connector_directory_path.mkdir(parents=True, exist_ok=True)
        test_settings_path = tests_connector_directory_path / "test_settings.py"
        test_settings_path.write_text(test_settings_content, encoding="utf-8")

    def _update_connector_connector_tmp(self):
        connector_tmp_path = self._find_file_path("connector.py.tmp")
        settings_tmp_path = self._find_file_path("settings.py.tmp")
        init_tmp_path = self._find_file_path("__init__.py.tmp")
        if not (connector_tmp_path and settings_tmp_path and init_tmp_path):
            raise RuntimeError(
                "File 'connector.py.tmp' or 'settings.py.tmp' or '__init__.py.tmp' not found"
            )

        connector_tmp_content = templates_adapters.src_connector_connector.get_content(
            self.connector_path, settings_tmp_path, init_tmp_path, self.entrypoint_path
        )
        connector_tmp_path.write_text(connector_tmp_content, encoding="utf-8")

    def _update_metadata_connector_manifest(self):
        manifest_path = self._find_file_path("connector_manifest.json")
        if not manifest_path:
            raise RuntimeError("File 'connector_manifest.json' not found")

        try:
            connector_manifest: dict = json.loads(manifest_path.read_text("utf-8"))
        except json.JSONDecodeError as e:
            raise RuntimeError("Invalid 'connector_manifest.json' content") from e

        connector_manifest["manager_supported"] = True

        manifest_path.write_text(
            json.dumps(connector_manifest, indent=2), encoding="utf-8"
        )

    def migrate_files(self):
        # ! Order of functions calls is important
        # ! some functions rely on files created in previous ones

        # Ensure all connectors have the same naming convention
        self._rename_docker_compose()
        self._rename_config_yaml_sample()

        # Ensure all connectors have valid root files
        self._update_docker_compose()
        self._update_config_yaml_sample()
        self._add_dot_env_sample()
        self._update_requirements_txt()

        # Migrate python files
        self._add_connector_connector_tmp()
        self._add_connector_settings_tmp()
        self._add_connector_common_tmp()
        self._add_connector_init_tmp()
        self._update_connector_connector_tmp()
        # Update entrypoint files
        self._add_main_tmp()
        self._add_init()  # for modules only

        # Add default unit tests (from templates)
        self._add_test_requirement_text()
        self._add_test_conftest()
        self._add_test_main()
        self._add_tests_settings()

        # Update metadata
        self._update_metadata_connector_manifest()

    def apply_ai_fixes(self):
        # ! Order of functions calls is important
        # ! some functions rely on files created in previous ones

        # Send codebase to OpenAI so it gets the context
        self.ai_assistant.send_codebase()

        # Fix `src` files
        settings_tmp_path = self._find_file_path("settings.py.tmp")
        if not settings_tmp_path:
            raise RuntimeError("File 'settings.py.tmp' not found")

        settings_tmp_content = self.ai_assistant.fix_connector_settings(
            settings_tmp_path
        )
        settings_tmp_path.write_text(settings_tmp_content, encoding="utf-8")

        connector_tmp_path = self._find_file_path("connector.py.tmp")
        if not connector_tmp_path:
            raise RuntimeError("File 'connector.py.tmp' not found")

        connector_tmp_content = self.ai_assistant.fix_connector(connector_tmp_path)
        connector_tmp_path.write_text(connector_tmp_content, encoding="utf-8")

        main_tmp_path = self._find_file_path("main.py.tmp") or self._find_file_path(
            "__main__.py.tmp"
        )
        if not main_tmp_path:
            raise RuntimeError("File 'main.py.tmp' not found")

        main_tmp_content = self.ai_assistant.fix_connector_main(main_tmp_path)
        main_tmp_path.write_text(main_tmp_content, encoding="utf-8")

        # Fix `tests` files
        test_settings_file_path = self._find_file_path("test_settings.py")
        if not test_settings_file_path:
            raise RuntimeError("File 'test_settings.py' not found")

        test_settings_file_content = self.ai_assistant.fix_connector_test_settings(
            test_settings_file_path
        )
        test_settings_file_path.write_text(test_settings_file_content, encoding="utf-8")

        test_main_file_path = self._find_file_path("test_main.py")
        if not test_main_file_path:
            raise RuntimeError("File 'test_main.py' not found")

        test_main_file_content = self.ai_assistant.fix_connector_test_main(
            test_main_file_path
        )
        test_main_file_path.write_text(test_main_file_content, encoding="utf-8")

    def cleanup_directory(self):
        for rootdir, dirs, files in os.walk(self.connector_path):
            # Modify dirs in place to skip ignored ones
            dirs[:] = [
                dir
                for dir in dirs
                if not (dir.startswith(".") or dir in CONNECTOR_IGNORED_SUBDIRECTORIES)
            ]

            # Remove `.tmp` extension from files
            for file in files:
                if file.endswith(".tmp"):
                    current_file_path = Path(rootdir) / file
                    current_file_content = current_file_path.read_text("utf-8")

                    # remove leading '.tmp' extension
                    new_file_path = Path(rootdir) / file.rstrip(".tmp")

                    # Unlink + write to avoid `FileExistsError` on Windows
                    current_file_path.unlink()
                    new_file_path.write_text(current_file_content, encoding="utf-8")

        bak_connector_path = Path(self.connector_path.as_posix() + "_bak")
        if os.path.exists(bak_connector_path):
            shutil.rmtree(bak_connector_path)

        remove_dead_code(self.connector_path)

    def format_files(self):
        src_path = self.connector_path / "src"
        tests_path = self.connector_path / "tests"
        returncode = subprocess.call(
            (
                f"autoflake --recursive --in-place {src_path} {tests_path} "
                f"&& black {src_path} {tests_path} "
                f"&& isort --profile black {src_path} {tests_path} "
                f"&& flake8 --ignore=E,W {src_path} {tests_path}"
            ),
            shell=True,
        )

        if returncode:
            raise RuntimeError("Error while formatting files")

    def restore(self):
        bak_connector_path = Path(self.connector_path.as_posix() + "_bak")
        if os.path.exists(bak_connector_path):
            shutil.rmtree(self.connector_path)
            os.rename(bak_connector_path, self.connector_path)
