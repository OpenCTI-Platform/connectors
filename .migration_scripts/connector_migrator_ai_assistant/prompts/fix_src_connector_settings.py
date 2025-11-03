from pathlib import Path


def get_prompt(file_path: Path) -> dict[str, str]:
    prompt = """
Fix the content of {file_path}, according to the guidance and the instructions below.

Guidance:
    This file contains Pydantic models. These models define the configuration of the connector and validate the given config vars at runtime.
    To determine if fixes are necessary, refer to:
        - `pydantic` (external-lib)
        - `docker-compose.yml`
        - `config.yml.sample`
        - `.env.sample`
        - `README.md`
        - `get_config_variable` method calls in the rest of the codebase
    
Instructions:
    1. keep the declarations of classes as is
        - DO NOT rename any classes
        - DO NOT change any classes' inheritance if any
    2. in the second model (i.e. the one inheriting from `BaseConfigModel`), add `description` to every fields
        - refer to `README.md` to get the description of the config vars
    3. in the second model (i.e. the one inheriting from `BaseConfigModel`), fix each field's type annotation to reflect expected type in the codebase
        - refer to `get_config_variable` calls in the codebase to determine the type of each field
        - refer to any statements using `self.config.<config_var>` in the codebase to determine the type of each field
        - MUST be `str` if the type can't be determined (CAN'T be `Any`)
    4. in the second model (i.e. the one inheriting from `BaseConfigModel`), add `default` to every fields
        - refer to `README.md`, especially in the `Environment variables` table, the value in the column `default`
        - refer to the 5th argument (`default` - `None` by default) of `get_config_variable` calls in the rest of the codebase
        - `default` value MUST be of the type declared for the field (except if the default is `None`)
        - `default` value MUST be wrapped by `SecretStr` type if the field is of type `SecretStr` 
        - if `default` value in lower case is the string "changeme", do not set any `default` (i.e. field is required)
        - if no default value is specified in the codebase, do not set any `default` (i.e. field is required)
        - if in `README.md`, especially in the `Environment variables` table, the value in the column `mandatory` or `required` is `False` or `❌`, do not set any `default` (i.e. field is required) 
    5. in the second model (i.e. the one inheriting from `BaseConfigModel`), add `deprecated=True` to deprecated fields
        - refer to `README.md`, especially in the `Environment variables` table, in the column 'description'
        - refer to `README.md`, especially in the `Environment variables` table, if the field is stroke (padded with `~~`)
    6. in the second model (i.e. the one inheriting from `BaseConfigModel`), update each field's type annotation to reflect if the field is optional or not
        - refer to `README.md`, especially the column `Mandatory` of the `Environment variables` table
        - refer to the 6th argument (`required` - `False` by default) of `get_config_variable` calls in the rest of the codebase
        - a field's type annotation MUST be changed to `<type> | None` if the field's `default` is explicitly set to `None`
        - a field's type annotation CAN'T be `<type> | None` if the field's default is not explicitly `None`
        - do not use `Optional` annotation from the built-in python module `typing`
""".format(
        file_path=file_path
    )

    return {"role": "user", "content": prompt}
