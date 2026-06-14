"""Make ``src/`` importable for the test modules in this directory.

Doing it once in ``conftest.py`` keeps the individual test modules free of
``sys.path`` boilerplate (which would otherwise trigger ``E402: module level
import not at top of file`` when run with the default flake8 configuration).
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
