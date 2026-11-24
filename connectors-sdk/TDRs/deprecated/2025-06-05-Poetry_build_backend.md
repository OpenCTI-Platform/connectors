# TDR: Use Poetry Build Backend for connectors-sdk

## Overview

This TDR proposes using **Poetry as the build backend** for this connectors-sdk project. The goal is to leverage Poetry's modern, reliable PEP 517-compliant build system to define and manage the build process through `pyproject.toml`, without depending on Poetry for environment or dependency management.

## Motivation

Python packaging has evolved toward standardization around `pyproject.toml` and PEP 517/518. Adopting a clean, tool-agnostic build backend is now best practice. Poetry offers a straightforward and well-supported backend for building packages, enabling compatibility with modern tools.

This change allows the project to define how it is built in a consistent and reproducible way, while maintaining flexibility for developers and CI systems to use any tool to install or manage the project.

## Proposed Solution

We will:

- Use `poetry.core.masonry.api` as the build backend in `pyproject.toml`
- Specify `build-system.requires` and `build-system.build-backend` sections according to PEP 517
- Ensure the installation will remain compatible with any compliant tool
.

## Advantages

- **Relative local dependencies packages installation**: Allows the developper to include local packages of the monorepo in the build process, which is useful for development and testing and development. (Currently, no other build backend supports this feature.)
- **Standard Compliance**: Aligns with modern Python packaging standards (PEP 517/518).
- **Tool Agnosticism**: Developers can use `pip`, `poetry`, or `build` independently of the backend.
- **Lightweight**: Does not introduce Poetry as a runtime or environment dependency.
- **Reproducibility**: Provides a reliable and deterministic build process.
- **IDE and CI Compatibility**: Works seamlessly with most modern Python IDEs and CI tools.

## Disadvantages

- **Perceived Coupling**: Developers unfamiliar with `pyproject.toml` might assume full Poetry usage, leading to confusion unless documented.

## Alternatives Considered

- **Setuptools**: Still widely used, but has historically been complex and less declarative. While modern `setuptools` has improved, Poetry's build backend is simpler and the only one that supports relative local dependencies.
- **Flit**: Lightweight and simple, but does not provide as much flexibility for more complex build scenarios.
- **Full Poetry Usage**: Rejected for now to avoid tool lock-in and unnecessary complexity for contributors who prefer using `pip`.

## References

- [PEP 517 – A build-system independent format for source trees](https://peps.python.org/pep-0517/) (consulted on 2025-06-05)
- [Poetry Core Documentation](https://python-poetry.org/docs/core/) (consulted on 2025-06-05)
- [Packaging Python Projects – PyPA](https://packaging.python.org/) (consulted on 2025-06-05)
- [Modern Python Packaging Guide](https://packaging.python.org/en/latest/tutorials/packaging-projects/) (consulted on 2025-06-05)
