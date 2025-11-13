# TDR: Typing and validation of configurations with Pydantic Settings

## Overview
This document outlines proposed changes to the configuration management of OpenCTI connectors. The historical `get_config_variable()` function will be replaced with a `Pydantic / Pydantic Settings` via `ConfigLoader`. 

This new approach offers centralised, typed and validated configuration, thereby reducing the risk of errors and providing greater control over connector configuration settings.

---

## Motivation

The historical function of retrieving variables via the `get_config_variable()` function did not offer strong typing or formal validation. This made configurations difficult to maintain, creating potential sources of errors and possible side effects.

Additionally, error handling related to configurations was not always explicit. This meant that errors sometimes occurred much later in the connector execution process, complicating diagnostics unnecessarily.

It was therefore necessary to adopt a modern solution that groups all configurations in a standardized and typed manner, with automatic validation during the initialization of each connector.

One of the advantages of using `Pydantic / Pydantic Settings` is the ability to easily convert validated variables into `JSON schema`. This standard ultimately allows the generation of manifests adapted to OpenCTI and the Integration Manager, thus facilitating the documentation and integration of connectors via the graphical interface.

The historical function:
```python
def get_config_variable(
        env_var: str,
        yaml_path: List,
        config: Dict = {},
        isNumber: Optional[bool] = False,
        default=None,
        required=False,
) -> Union[bool, int, None, str]:
    """[summary]

    :param env_var: environment variable name
    :param yaml_path: path to yaml config
    :param config: client config dict, defaults to {}
    :param isNumber: specify if the variable is a number, defaults to False
    :param default: default value
    """

    if os.getenv(env_var) is not None:
        result = os.getenv(env_var)
    elif yaml_path is not None:
        if yaml_path[0] in config and yaml_path[1] in config[yaml_path[0]]:
            result = config[yaml_path[0]][yaml_path[1]]
        else:
            return default
    else:
        return default

    if result in TRUTHY:
        return True
    if result in FALSY:
        return False
    if isNumber:
        return int(result)

    if (
            required
            and default is None
            and (result is None or (isinstance(result, str) and len(result) == 0))
    ):
        raise ValueError("The configuration " + env_var + " is required")

    if isinstance(result, str) and len(result) == 0:
        return default

    return result
```

Disadvantage of this historical function:
- No strong typing: heterogeneous return types (`bool`, `int`, `str` and `None`).
- Limited validation and error handling: only the `required` parameter generates an explicit error. There are no advanced checks for negative values, invalid formats, etc.
- Type conversion is often manual: Type conversion often had to be done manually in the connector (e.g. `int(...), bool(...)`).

Example of use: 
```python
# OpenCTI configurations  
self.duration_period = get_config_variable(  
    env_var="CONNECTOR_DURATION_PERIOD",  
    yaml_path=["connector", "duration_period"],  
    config=self.load,
    required=True,
    default="P1D",
)
```

---

## Proposed Solution

Replace the `get_config_variable()` function with a single `Pydantic / Pydantic Settings` based model.

Using Pydantic Settings enables you to define a configuration class that can handle multiple formats and sources of configuration files naturally. This typed model ensures on-the-fly data validation and returns clear error messages when problems arise. It also provides consistent access to settings throughout the project. This solution will be integrated into the connector by replacing direct calls to `get_config_variable()` with instantiation of one or more dedicated Pydantic models.

The example below illustrates a basic Pydantic environment variable configuration:
```python
class _ConfigLoaderOCTI(ConfigBaseSettings):  
    """Interface for loading OpenCTI dedicated configuration."""  
  
    # Config Loader OpenCTI    
    url: HttpUrlToString = Field(  
        description="The OpenCTI platform URL.",  
    )  
    token: str = Field(  
        description="The token of the user who represents the connector in the OpenCTI platform.",  
    )
```

Example of explicit Pydantic / Pydantic Settings errors in the configuration if fields are missing:
```sh
pydantic_core._pydantic_core.ValidationError: 2 validation errors for _ConfigLoaderOCTI
url
  Field required [type=missing, input_value={}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.11/v/missing
token
  Field required [type=missing, input_value={}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.11/v/missing
```


---

## Advantages

- Standardisation and unification of sources: all configurations are loaded via a single template, regardless of the source file (environment variables, .env files, config.yml, Docker Compose, etc.).

- Strong typing: variables are strictly typed (int, str, bool, etc.), which prevents errors caused by manual conversions or configuration file format inconsistencies (for example, Docker compose always treats variables as strings).

- Automatic validation and explicit errors: parameters are validated on loading, with explicit errors if values are missing or invalid.

- Compatible with different environments: local, Docker, CI/CD and other environments are managed consistently.

- Quick JSON Schema generation: the typed configuration structure can be automatically exported to JSON Schema format, facilitating the generation of documentation and manifests, and improving integration with external tools.

- Fewer errors and more control: Pydantic Settings is a more modern and robust alternative to the outdated get_config_variable() function, which relies on manual and partial management of types, missing values and priorities.

- Ease of extension: It is quick and easy to add new parameters to the Pydantic model. Simply define new typed fields in the configuration class to do so, without modifying the loading or validation logic.

---

## Disadvantages

- There is a dependency on an external library Pydantic / Pydantic Settings, which means that the connectors are tied to its lifecycle, updates and compatibility.
- It requires unfamiliar developers to learn Pydantic / Pydantic Settings.
- Initial integration may take longer than with the simple variable retrieval method.
- It can sometimes be a little heavier in terms of abstraction and startup overhead.

---

## Alternatives Considered

- Keep, transform and maintain the more complex, less robust and higher-risk-of-side-effects `get_config_variable()`.

---

## References
- [Pydantic Documentation](https://docs.pydantic.dev/latest/) (consulted on 2025-10-01)
- [Pydantic Settings Documentation](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) (consulted on 2025-10-01)
- [Pydantic JSON Schema](https://docs.pydantic.dev/latest/concepts/json_schema/) (consulted on 2025-10-01)

---
