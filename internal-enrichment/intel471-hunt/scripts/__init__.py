"""Developer CLI tooling for the Intel 471 Hunter connector.

Nothing in this package is part of the connector runtime: these are local
smoke-test / dry-run helpers, they are not imported by ``src`` and they are not
shipped in the container image (the Dockerfile only copies ``src``).

Run them as modules from the connector directory so ``src`` stays importable::

    python -m scripts.dry_run --help
    python -m scripts.hunter_client_cli --help
"""
