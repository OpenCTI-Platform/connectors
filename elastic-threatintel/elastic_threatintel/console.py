#!/usr/bin/env python3
"""
Usage:  elastic-threatintel-connector [-v | -vv | -vvv | -q | --debug] [-c FILE] [-d DIR]
        elastic-threatintel-connector --version

Runs OpenCTI connector using provided config.yml file. See config.yml.reference
for full configuration options and optional environment variables.

Options:
  -h --help                   show this help message and exit
  --version                   show version and exit
  -c FILE --config=FILE       path to configuration YAML [default: config.yml]
  -d DIR --data-dir=DIR       path to data directory for Elasticsearch templates [default: ./data]
  -v                          increase verbosity (can be used up to 3 times)
  -q                          quiet mode
  --debug                     enable debug logging for all Python modules
"""

import os
import sys
from importlib.metadata import version
from logging import getLogger

import yaml
from docopt import docopt

from . import __version__
from .elastic_threatintel import ElasticThreatIntelConnector
from .utils import setup_logger

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


def run():
    pycti_ver: str = version("pycti")
    my_version: str = (
        f"elastic-threatintel-connector  {__version__}\n" f"pyopencti  {pycti_ver}"
    )
    arguments: dict = docopt(__doc__, version=my_version)
    verbosity: int = 20

    if not arguments["-q"] is True:
        """
        Level    | Value
        ---------|---------
        CRITICAL | 50
        ERROR    | 40
        WARNING  | 30
        INFO     | 20
        DEBUG    | 10
        NOTSET   | 0
        """
        verbosity = 30 + (arguments["-v"] * -10)
        if verbosity == 0:
            verbosity = 1
    else:
        verbosity = 40

    logger_name = "elastic-threatintel-connector"
    if arguments["--debug"] is True:
        # Enable full logging for all loggers
        logger_name = None
        verbosity = 10

    setup_logger(verbosity=verbosity, name=logger_name)
    logger = getLogger(name=logger_name)

    # This can be overridden by environment variables
    config = {}
    if not os.path.exists(arguments["--config"]):
        logger.warn(f"""Config file '{arguments["--config"]}' does not exist""")
    elif not os.path.isfile(arguments["--config"]):
        logger.warn(f"""'{arguments["--config"]}' is not a file for --config""")
    else:
        config = yaml.load(open(arguments["--config"]), Loader=yaml.FullLoader)

    # This can be overridden by environment variables
    datadir = None
    if not os.path.exists(arguments["--data-dir"]):
        logger.warn(f"""Data directory '{arguments["--data-dir"]}' does not exist.""")
    elif not os.path.isdir(arguments["--data-dir"]):
        logger.warn(
            f"""'{arguments["--data-dir"]}' is not a valid directory for --data-dir"""
        )
    else:
        datadir = arguments["--data-dir"]

    if not arguments["-q"] is True:
        print(BANNER)
    ElasticInstance = ElasticThreatIntelConnector(config=config, datadir=datadir)
    ElasticInstance.start()

    sys.exit(0)
