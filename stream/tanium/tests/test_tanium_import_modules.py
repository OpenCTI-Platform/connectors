import os
import sys

# Addition of the src directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))


def test_imports():
    """
    Dummy test to roughly check there is no syntax error or recursive imports
    """
    import import_manager  # noqa: F401
    import intel_cache  # noqa: F401
    import sightings  # noqa: F401
    import tanium  # noqa: F401
    import tanium_api_handler  # noqa: F401
