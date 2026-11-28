# TDR: Use the uv Build Backend for connectors-sdk

## Overview

This TDR replaces Poetry (`poetry-core`) with uv (`uv_build`) as the build backend of `connectors-sdk`. It supersedes [Use Poetry Build Backend for connectors-sdk](deprecated/2025-06-05-Poetry_build_backend.md).

The SDK still builds through PEP 517, so `pip install`, `python -m build` and git URL installs keep working unchanged.

---

## Motivation

- uv is already the tool of the repository: `run_test.sh` creates its venvs and installs with `uv pip`, CI runs the linters with `uvx`, and `mise` installs uv. Poetry was only kept to build the SDK.
- The main reason for choosing Poetry was its support for relative path dependencies. The SDK has none, and connectors depend on the SDK through a git URL or, soon, a PyPI version, not through a path declared in the SDK's own metadata.
- Poetry needs a `[tool.poetry]` section next to `[project]`, including a `tool.poetry.version` that duplicates the `dynamic` version. Two places for one version are confusing, and the publishing work (#8464) has to rewrite the version before each release build.
- Using the same tool to build and to publish (`uv build`, `uv publish`) keeps the release workflow small.

---

## Proposed Solution

In `connectors-sdk/pyproject.toml`:

- `build-system.requires = ["uv_build>=0.13.0,<0.14"]` and `build-backend = "uv_build"`. The upper bound follows the uv documentation: the backend's behaviour may change between minor versions, so upgrades are deliberate.
- The version is static in `[project]` (`version = "0.0.0"`). `uv_build` does not support dynamic versions. The value is a placeholder that the release workflow replaces with the released version before building.
- The flat layout and the two top-level packages are declared in `[tool.uv.build-backend]` (`module-root = ""`, `module-name = ["connectors_sdk", "_connectors_sdk_plugins"]`).
- The `[tool.poetry]` section is removed, and so is Poetry from `.mise/config.toml`.

The wheel and sdist contain the same modules and the same `pytest11` entry point as with Poetry. Differences in metadata:

- Poetry added `Programming Language :: Python :: 3.x` classifiers derived from `requires-python`. `uv_build` writes only the classifiers declared in `[project]`.
- In the sdist, `uv_build` writes a normalized `pyproject.toml` and keeps the original as `pyproject.toml.orig`.

---

## Advantages

- **One tool**: the same uv that runs the tests builds and publishes the SDK.
- **Standard metadata only**: everything lives in `[project]`, with no backend-specific copy of the version or of the package list.
- **Fast and strict**: `uv_build` validates the package layout and fails on a missing or misnamed module instead of building an empty wheel.
- **Tool agnosticism kept**: any PEP 517 frontend (pip, build, uv) can still build and install the SDK.

---

## Disadvantages

- **Native backend**: `uv_build` is a compiled package. pip downloads a platform wheel at build time, which exists for the platforms used here (manylinux and musllinux on x86_64 and aarch64, macOS, Windows). On a platform without a wheel, building would need a Rust toolchain.
- **Version bound to maintain**: the `<0.14` bound has to be raised when a new minor version of uv is adopted.
- **No build hooks or dynamic metadata**: a future need for generated files or a version computed at build time would require another backend.

---

## Alternatives Considered

- **Keep `poetry-core`**: works, but keeps a second tool and the duplicated version for no remaining benefit.
- **Hatchling**: mature, pure Python and supports dynamic versions through plugins, but adds yet another tool when uv is already used everywhere else.
- **setuptools-scm (dynamic version from git tags)**: rejected while reviewing #8465. Release tags point to a commit that sits on no branch, so no release tag is reachable from `master` or `lts/*`, and git installs would report a wrong development version.

---

## References

- [uv build backend](https://docs.astral.sh/uv/concepts/build-backend/) (consulted on 2026-11-24)
- [PEP 517 – A build-system independent format for source trees](https://peps.python.org/pep-0517/) (consulted on 2026-11-24)
- [Review discussion on #8465](https://github.com/OpenCTI-Platform/connectors/pull/8465#discussion_r4630460719) (consulted on 2026-11-24)

---
