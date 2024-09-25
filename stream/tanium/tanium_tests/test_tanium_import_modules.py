import pytest  # noqa: F401


def test_imports():
    """
    Dummy test to roughly check there is no syntax error or recursive imports
    """
    import src.import_manager  # noqa: F401
    import src.intel_cache  # noqa: F401
    import src.sightings  # noqa: F401
    import src.tanium  # noqa: F401
    import src.tanium_api_handler  # noqa: F401
