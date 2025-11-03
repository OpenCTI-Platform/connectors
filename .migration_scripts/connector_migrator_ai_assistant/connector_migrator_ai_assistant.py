import os
from pathlib import Path
from typing import Any

from connector_migrator_ai_assistant import prompts
from openai import APIStatusError, OpenAI  # if not found run `pip install openai`

CONNECTOR_IGNORED_SUBDIRECTORIES = [
    "__metadata__",
    "__pycache__",
    "venv",
]


class ConnectorMigratorAIAssistant:
    def __init__(self, connector_path: Path):
        self.connector_path = connector_path

        self.client = OpenAI(
            base_url=os.environ.get("OPENAI_BASE_URL"),
            api_key=os.environ.get("OPENAI_API_KEY"),
        )
        self.messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": "After your first answer, answer ONLY with a code block, without any additional text or explanation. "
                "As your answers will be parsed programatically, ALWAYS use the same message format, i.e. "
                "for each given filepath, the code block containing the full content of the modified file."
                "The code should be ready to be copied locally to the given filepath and used directly.",
            },
            {
                "role": "system",
                "content": "You will receive the next messages in the form of a filepath and a code block containing all the code in this file. "
                "All these messages represent the codebase of an OpenCTI connector. Consider `.py.tmp` files as normal executable python files. "
                "Impersonate a developer that need to fix the codebase of the connector and make the tests pass. "
                "All the code that you will provide MUST be applicable in place in this codebase. "
                "Propose ONLY fixes that strictly follow the instructions. You CAN'T rename imports, classes, methods, variables, etc unless explictly asked to. "
                "Consider all the code blocks in your answers accepted as is and that the codebase is updated immediately, like if run `git add .`.",
            },
        ]

    def _send_messages(self) -> str:
        try:
            response = self.client.chat.completions.create(
                model="codestral-latest",
                messages=self.messages,  # type: ignore
            )
            response_message = response.choices[0].message
            if not response_message or not response_message.content:
                raise RuntimeError("No response from AI assistant")

            self.messages.append(response_message.to_dict())

            # Get code only (inside code block delimiters, i.e. "```")
            return response_message.content.strip("`")
        except APIStatusError as e:
            # Timeout errors are retired twice by default, after last retry, raise exception
            raise RuntimeError(
                f"OpenAI API error: {e.status_code} - {e.message}"
            ) from e

    def send_codebase(self):
        connector_root_files = [
            ".env.sample",
            "config.yml.sample",
            "docker-compose.yml",
            "README.md",
        ]

        connector_files_paths: list[Path] = []
        for rootdir, dirs, files in os.walk(self.connector_path):
            # Modify dirs in place to skip ignored ones
            dirs[:] = [
                dir
                for dir in dirs
                if not (dir.startswith(".") or dir in CONNECTOR_IGNORED_SUBDIRECTORIES)
            ]

            # Look for file in allowed dirs
            for file in files:
                if file in connector_root_files:
                    connector_files_paths.append((Path(rootdir) / file))
                if file.endswith(".tmp"):
                    connector_files_paths.append((Path(rootdir) / file))
            for file in files:
                if file.endswith(".py") and file + ".tmp" not in files:
                    connector_files_paths.append((Path(rootdir) / file))

        for connector_file_path in connector_files_paths:
            file_content = connector_file_path.read_text(errors="ignore")
            self.messages.append(
                {
                    "role": "system",
                    "content": f"{connector_file_path}\n```{file_content}```",
                }
            )

        self.messages.append(
            {
                "role": "system",
                "content": "You received all the files' content of the codebase. Answer 'ok' to confirm.",
            },
        )

        self._send_messages()

    def fix_connector_settings(self, file_path: Path) -> str:
        self.messages.append(prompts.fix_src_connector_settings.get_prompt(file_path))
        return self._send_messages()

    def fix_connector(self, file_path: Path) -> str:
        self.messages.append(prompts.fix_src_connector.get_prompt(file_path))
        return self._send_messages()

    def fix_connector_main(self, file_path: Path) -> str:
        self.messages.append(prompts.fix_src_main.get_prompt(file_path))
        return self._send_messages()

    def fix_connector_test_settings(self, file_path: Path) -> str:
        self.messages.append(prompts.fix_tests_test_settings.get_prompt(file_path))
        return self._send_messages()

    def fix_connector_test_main(self, file_path: Path) -> str:
        self.messages.append(prompts.fix_tests_test_main.get_prompt(file_path))
        return self._send_messages()
