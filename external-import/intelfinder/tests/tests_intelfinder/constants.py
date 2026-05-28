import json
import logging
import os
import random
import string

LOGGER = logging.getLogger(__name__)
DEFAULT_TLP = "TLP:WHITE"


# import fixture from local directory fixtures
def load_fixture(filename):
    """Load a fixture file and return its content."""
    filepath = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fixture {filename} not found.")
    with open(filepath, "r") as file:
        content = file.read()
        if not content.strip():
            raise ValueError(f"Fixture {filename} is empty.")
        return json.loads(content)


def generate_random_key():
    """Generate random alpha-numeric key of length 24."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=24))
