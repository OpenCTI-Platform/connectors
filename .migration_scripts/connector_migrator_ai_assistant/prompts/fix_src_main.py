from pathlib import Path


def get_prompt(file_path: Path) -> dict[str, str]:
    prompt = """
Fix the content of {file_path}, according to the guidance and the instructions below.

Guidance:
    This file is the entrypoint of the application.
    To start the application, this file must instantiate `ConnectorSettings`, `OpenCTIConnectorHelper` and the connector's main class.
    Then the entrypoint method of connector's main class is called to start the connector.

Instructions:
    1. fix the class name of the instance stored in the variable `connector`
        - MUST be the connector's main class name
    2. replace `connector.run()` with the right entrypoint method if `connector` does not have a `run` method
        - refer to the file containing the connector's main class
        - the method to use is the one starting the connector and executing the callback function (usually named `run`, `start`, `main`, etc)
""".format(
        file_path=file_path
    )

    return {"role": "user", "content": prompt}
