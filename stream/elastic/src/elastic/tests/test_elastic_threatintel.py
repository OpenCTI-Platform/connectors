from importlib.metadata import version

from elastic import __version__


def test_version():
    """Ensure Connector version matches pycti version. If this fails, check __version__ in __init__.py and pycti version in pyproject.toml"""
    pycti_ver: str = version("pycti")
    assert __version__ == pycti_ver
