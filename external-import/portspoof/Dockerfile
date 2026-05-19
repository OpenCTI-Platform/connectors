FROM python:3.11-slim
WORKDIR /app

# Install system dependencies. ``libmagic1`` is required by ``pycti``;
# ``git`` is required because the repository's CircleCI dynamic
# templates may rewrite the pinned ``pycti==X.Y.Z`` line to
# ``pycti @ git+https://...`` for rolling / prerelease builds (see
# ``.circleci/templates/dynamic.yml.j2``), and pip needs the ``git``
# binary on PATH to install VCS dependencies. Both apt packages are
# installed and the apt cache is purged in the same layer so the
# final image stays small.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 git && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./
CMD ["python", "-u", "main.py"]