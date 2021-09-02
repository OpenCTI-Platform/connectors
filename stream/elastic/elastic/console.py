#!/usr/bin/env python3
"""
Usage:  elastic [-v | -vv | -vvv | -q | --debug] [-c FILE] [-d DIR]
        elastic --version

Runs OpenCTI connector using provided config.yml file. See config.yml.reference
for full configuration options and optional environment variables.

Options:
  -h --help                   show this help message and exit
  --version                   show version and exit
  -c FILE --config=FILE       path to configuration YAML [default: config.yml]
  -d DIR --data-dir=DIR       path to data directory for Elasticsearch templates (uses module data by default)
  -v                          increase verbosity (can be used up to 3 times)
  -q                          quiet mode
  --debug                     enable debug logging for all Python modules
"""

import json
import logging
import os
import sys
from importlib.metadata import version
from typing import OrderedDict

import yaml
from docopt import docopt

from . import LOGGER_NAME, __version__, __DATA_DIR__
from .conf import defaults
from .elastic import ElasticConnector
from .utils import add_branch, dict_merge, remove_nones, setup_logger

BANNER = f"""

        ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
        ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
        ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          _______ _                   _
        ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓         (_______) |              _  (_)
        ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          _____  | | _____  ___ _| |_ _  ____
                      ▓▓▓▓▓▓▓▓▓▓▓▓         |  ___) | |(____ |/___|_   _) |/ ___)
░░░░░░░░██████████    ▓▓▓▓▓▓▓▓▓▓▓▓         | |_____| |/ ___ |___ | | |_| ( (___
░░░░░░░░██████████    ▓▓▓▓▓▓▓▓▓▓▓▓         |_______)\\_)_____(___/   \\__)_|\\____)
░░░░░░░░██████████    ▓▓▓▓▓▓▓▓▓▓▓▓
░░░░░░░░██████████    ▓▓▓▓▓▓▓▓▓▓▓▓           ______                         _
░░░░░░░░██████████    ▓▓▓▓▓▓▓▓▓▓▓▓          / _____)                       (_)  _
░░░░░░░░██████████    ▓▓▓▓▓▓▓▓▓▓▓▓         ( (____  _____  ____ _   _  ____ _ _| |_ _   _
░░░░░░░░██████████    ▓▓▓▓▓▓▓▓▓▓▓▓          \\____ \\| ___ |/ ___) | | |/ ___) (_   _) | | |
░░░░░░░░░█████████    ▓▓▓▓▓▓▓▓▓▓            _____) ) ____( (___| |_| | |   | | | |_| |_| |
 ░░░░░░░░░░░██████    ▓▓▓▓▓▓▓              (______/|_____)\\____)____/|_|   |_|  \\__)\\__  |
  ░░░░░░░░░░░░░███    ▓▓▓▓                                                         (____/
   ░░░░░░░░░░░░░░░
     ░░░░░░░░░░░░░
        ░░░░░░░░░░                          Elastic OpenCTI Connector, version {__version__}
           ░░░░░░░
               ░░░
"""


def __process_config(argv={}, config={}) -> dict:
    """
    Order of precedence:
        Environment variables override command line options
        Command line options override configuration file values
        Configuration file values override defaults
    """

    logger = logging.getLogger(LOGGER_NAME)
    # Get defaults, update with file config
    _conf: dict = dict_merge(defaults, config)
    logger.debug(f"Post-config merging:\n {json.dumps(_conf)}")

    # Skipping the other OpenCTI values since the helper handles them
    _env = {
        "connector": {
            "log_level": os.environ.get("CONNECTOR_LOG_LEVEL", None),
            "confidence_level": os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", None),
            "mode": os.environ.get("CONNECTOR_MODE", None),
        },
        "cloud": {
            "auth": os.environ.get("CLOUD_AUTH", None),
            "id": os.environ.get("CLOUD_ID", None),
        },
        "output": {
            "elasticsearch": {
                "api_key": os.environ.get("ELASTICSEARCH_APIKEY", None),
                "hosts": os.environ.get("ELASTICSEARCH_HOSTS", "").split(","),
                "username": os.environ.get("ELASTICSEARCH_USERNAME", None),
                "password": os.environ.get("ELASTICSEARCH_PASSWORD", None),
                "ssl_verify": os.environ.get("ELASTICSEARCH_SSL_VERIFY", None),
            }
        },
        "elastic": {
            "import_label": os.environ.get("ELASTIC_IMPORT_LABEL", None),
            "import_from_date": os.environ.get("ELASTIC_IMPORT_FROM_DATE", None),
        },
    }

    if _env["connector"]["log_level"] is not None:
        _env["connector"]["log_level"] = _env["connector"]["log_level"].upper()

    logger.debug(f"Raw ENV config:\n {json.dumps(_env)}")

    _env = remove_nones(_env)
    _conf: dict = dict_merge(_conf, _env)

    logger.debug(f"Merged ENV config:\n {json.dumps(_conf)}")

    # This var overrides everything
    if os.environ.get("CONNECTOR_JSON_CONFIG", None):
        _jsonenv = json.loads(os.environ.get("CONNECTOR_JSON_CONFIG"))
        _conf: dict = dict_merge(_conf, _jsonenv)

    return _conf


def main() -> None:
    pycti_ver: str = version("pycti")
    elastic_ver: str = version("elasticsearch")
    my_version: str = (
        f"elastic  {__version__}\n"
        f"pyopencti                      {pycti_ver}\n"
        f"elasticsearch                  {elastic_ver}\n"
    )
    arguments: dict = docopt(__doc__, version=my_version)
    _verbosity: int = 0
    if not arguments["-q"] is True:
        _verbosity = 30 + (arguments["-v"] * -10)
        # If this is set to 0, it defaults to the root logger configuration,
        # which we don't want to manipulate because it will spam from other modules
        if _verbosity == 0:
            _verbosity = 1
    else:
        _verbosity = 40

    _loggername = LOGGER_NAME
    if arguments["--debug"] is True:
        # Enable full logging for all loggers
        _loggername = None
        _verbosity = 10

    setup_logger(verbosity=_verbosity, name=_loggername)
    logger = logging.getLogger(LOGGER_NAME)

    # This can be overridden by environment variables
    f_config: OrderedDict = {}
    if not os.path.exists(arguments["--config"]):
        logger.warn(
            f"""Config file '{arguments["--config"]}' does not exist. Relying on environment and defaults."""
        )
    elif not os.path.isfile(arguments["--config"]):
        logger.warn(
            f"""Config path '{arguments["--config"]}' exists but is not a file. Relying on environment and defaults."""
        )
    else:
        f_config = yaml.load(open(arguments["--config"]), Loader=yaml.FullLoader)

    if "connector" not in f_config:
        f_config["connector"] = {}
        f_config["connector"]["log_level"] = (
            logging.getLevelName(_verbosity) if _verbosity != 1 else "TRACE"
        )

    config: dict = {}
    for k, v in f_config.items():
        config = add_branch(config, k.split("."), v)

    config = __process_config(arguments, config)

    # Check if we need to update logger config
    if logging.getLevelName(logger.level) != config["connector"]["log_level"]:
        logger.setLevel(config["connector"]["log_level"].upper())

    logger.trace(json.dumps(config, sort_keys=True, indent=4))

    # This can be overridden by environment variables
    datadir = __DATA_DIR__
    if "--data-dir" in arguments and arguments["--data-dir"] is not None:
        if not os.path.exists(arguments["--data-dir"]):
            logger.warn(
                f"""Data directory '{arguments["--data-dir"]}' does not exist."""
            )
        elif not os.path.isdir(arguments["--data-dir"]):
            logger.warn(
                f"""'{arguments["--data-dir"]}' is not a valid directory for --data-dir"""
            )
        else:
            datadir = arguments["--data-dir"]
    else:
        logger.info(f"Using default data directory: {datadir}")

    if not arguments["-q"] is True:
        print(BANNER)

    # If we're using the custom TRACE level, just tell OpenCTI to run as DEBUG
    if config["connector"]["log_level"] == "TRACE":
        os.environ["CONNECTOR_LOG_LEVEL"] = "DEBUG"

    ElasticInstance = ElasticConnector(config=config, datadir=datadir)
    ElasticInstance.start()

    sys.exit(0)


if __name__ == "__main__":
    main()
