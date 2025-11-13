# TDR: Model Registry to Handle OCTI Models Nested Definitions

## Overview

This TDR outlines the decision to use a `MODEL_REGISTRY` to address the issue of Pydantic models not being fully defined when dealing with nested definitions.

---

## Motivation

Pydantic models can encounter errors when nested definitions are not fully resolved during initialization. This issue arises due to circular dependencies or delayed definitions in nested models. Using a `MODEL_REGISTRY` provides a centralized mechanism to manage and resolve these definitions, avoiding runtime errors and improving model reliability.

---

## Proposed Solution

The solution involves implementing a `MODEL_REGISTRY` that acts as a repository for all Pydantic models.

- Registering models in the `MODEL_REGISTRY` upon creation.
- Resolving nested definitions dynamically using the registry.
- Ensuring that all models are fully defined before usage.

For an entity defintion, the registration process would look like this:

```python
from connectors_sdk.models.octi._common import MODEL_REGISTRY, BaseEntity

@MODEL_REGISTRY.register
class MyNestedModel(BaseEntity):
    ...

...

# End of module
MODEL_REGISTRY.rebuild_all

```

> [!TIP]
> The registered models is also rebuilt in the `connectors_sdk.models.octi` public API.

---

## Advantages

- Eliminates errors caused by undefined nested models.
- Simplifies the management of complex model hierarchies.
- Improves code maintainability.
- Provides a centralized mechanism for model resolution.

---

## Disadvantages

- Introduces additional complexity in managing the `MODEL_REGISTRY`.
- Requires developers to adhere to the registration process for all models.
- Potential performance overhead for dynamic resolution.

---

## Alternatives Considered

- Manual Resolution of Nested Models: This approach is error-prone and difficult to maintain for large-scale projects.
- Use of `__init_subclass__`: Using the __init__subclass method in `BaseIdentifiedEntity` register models was considered and less verbose for developer that would not have to manually register models. However, the `REGISTRY_MODEL.rebuild_all` method would still need to be called at the end of the module to ensure all models are registered and fully defined. To remind developers the explicit registration process, is prefered.

---

## References

- [Pydantic classnot fully defined guide](https://docs.pydantic.dev/2.11/errors/usage_errors/#class-not-fully-defined) (consulted on 2025-06-09)
- [Model Registry Solution from cordery](https://github.com/pydantic/pydantic/discussions/11776#discussion-8218609) (consulted on 2025-06-09)
- [PEP 487](https://peps.python.org/pep-0487/)

---
