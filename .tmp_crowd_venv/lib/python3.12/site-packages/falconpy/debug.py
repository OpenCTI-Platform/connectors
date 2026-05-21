"""Interactive debugger for the crowdstrike-falconpy project.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""
import os
import sys
import importlib
import atexit
from logging import Logger, basicConfig, getLogger, DEBUG
# from os.path import dirname, join
# import glob
from . import oauth2 as FalconAuth


def help(item=None):  # pylint: disable=W0622
    """Debugger help function. Overrides the built in python function."""
    text = """
    This is an interactive Python shell. Python help is available under python_help().

    AUTHENTICATION
    If you have FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables set,
    this shell will authenticate you at start up. You can also call the init()
    function passing the values dbg_falcon_client_id and dbg_falcon_client_secret, or
    you can pass a credential dictionary containing them.

    AVAILABLE VARIABLES
        'DEBUG_TOKEN' - your OAuth2 token.
        'AUTH' - an instance of the OAuth2 authorization object (authenticated).

    LISTING AVAILABLE CLASSES
    Use list_modules() to retrieve a list of all available classes.

    ALL CLASSES ARE IMPORTED AND AVAILABLE FOR TESTING.

    Create an instance of the Hosts Service Class and query for devices:
    In [1]: hosts = Hosts(auth_object=AUTH)
    In [2]: hosts.query_devices_by_filter_scroll(filter="hostname:'whatever'")

    Using the Detects Service Class to query for all available detections with one command:
    In [1]: Detects(auth_object=AUTH).query_detects()

    EXIT THE DEBUGGER
    Use exit / quit / CTRL-D to exit the debugger.
    """
    if item is None:
        print(text)
    elif callable(getattr(item, 'help', None)):
        item.help()
    else:
        print(item.__doc__)


def embed():
    """Embed the IPython interactive shell."""
    _ = importlib.import_module("IPython.terminal.embed")
    ipshell = _.InteractiveShellEmbed(banner1=BANNER)
    ipshell.confirm_exit = False
    ipshell()


def setup_logging() -> Logger:
    """Configure simple logging."""
    log_util = getLogger("log_testing")
    basicConfig(level=DEBUG, format="%(asctime)s %(levelname)-8s %(name)s %(funcName)s %(message)s")

    return log_util


def list_modules():
    """List all available Service Classes."""
    # modules = glob.glob(join(dirname(__file__), "*.py"))
    # Only importing within this method to load the classes for the debugger not-package code.
    # pylint: disable=C0415,E0401
    import src.falconpy
    result = [x for x in dir(src.falconpy) if ("_" not in x and not x.islower())]
    # result = []
    # for key in modules:
    #     branched = key.split("/")
    #     position = len(branched)-1
    #     module_name = branched[position].replace(".py", "")
    #     if "_" not in module_name[0] and module_name not in ["debug", "api_complete"]:
    #         result.append(module_name)
    result.sort()
    print("\nAvailable FalconPy classes")
    print(f"{'=' * 65}")
    msg = ""
    for idx, val in enumerate(result):
        msg = f"{msg}%-35s" % val
        cnt = idx + 1
        if cnt % 2 == 0:
            print(msg)
            msg = ""
    print(msg)
    print("\nLoad modules with import_module('MODULE_NAME')")


def import_all():
    """Inspect the package folder and import all available classes from all modules."""
    # Only importing within this method to load the classes for the debugger not-package code.
    # pylint: disable=C0415,E0401,R1702
    try:
        import src.falconpy as sdk
    except ImportError:
        # We're running via the package prolly
        import falconpy as sdk
    import inspect
    loaded = []
    for name, obj in inspect.getmembers(sdk, inspect.isclass):
        # This is uh... interesting.
        mod_name = f"{obj}".replace("<class", "").replace(">", "").replace("'", "").strip().replace(f".{name}", "")
        if "enum" not in mod_name:
            try:
                module = importlib.import_module(mod_name)
                for attribute_name in [x for x in dir(module) if "__" not in x]:
                    attribute = getattr(module, attribute_name)
                    if inspect.isclass(attribute):
                        if attribute_name not in loaded:
                            globals()[attribute_name] = attribute
                            log.debug("Loaded %s class", attribute_name)
                            loaded.append(attribute_name)

            except ImportError:
                # Probably one of the aliases
                log.debug("Skipped %s alias", name)


def import_module(module: str = None):
    """Dynamically imports the module requested and returns an authenticated instance of the Service Class."""
    returned_object = False
    found = False
    if module:
        module = module.lower()
        import_location = "src.falconpy"
        try:
            # Assume they're working from the repo first
            _ = [importlib.import_module(f"{import_location}.{module}")]
            found = True
        except ImportError:
            try:
                import_location = "falconpy"
                # Then try to import from the installed module
                _ = [importlib.import_module(f"{import_location}.{module}")]
                found = True
            except ImportError:
                print("Unable to import requested service class")
        if found:
            current_module = sys.modules[f"{import_location}.{module}"]
            for key in dir(current_module):
                if isinstance(getattr(current_module, key), type) and not key == "ServiceClass" and "_" not in key:
                    _.append(getattr(_[0], key))
                    returned_object = _[1](auth_object=AUTH)
                    print(f"Service Class {key} imported successfully.")
    else:
        print("No module specified.")

    return returned_object


def exit_handler():
    """Revoke the DEBUG_TOKEN and gracefully quit the debugger. Overrides the built in python function."""
    if AUTH:
        print("Discarding token")
        AUTH.revoke(token=DEBUG_TOKEN)
    sys.exit(0)


def startup(dbg_falcon_client_id: str, dbg_falcon_client_secret: str):
    """Authenticate using the credentials provided and return the token / authentication object."""
    auth_object = FalconAuth.OAuth2(client_id=dbg_falcon_client_id,
                                    client_secret=dbg_falcon_client_secret,
                                    debug=True
                                    )

    try:
        debug_token = auth_object.token()["body"]["access_token"]
    except KeyError:
        debug_token = False
        auth_object = False

    return debug_token, auth_object


def init(dbg_falcon_client_id: str = None, dbg_falcon_client_secret: str = None, creds: dict = None):
    """Initialize the debugger by retrieving any available credentials and performing initial authentication."""
    if creds:
        dbg_falcon_client_id = creds["falcon_client_id"]
        dbg_falcon_client_secret = creds["falcon_client_secret"]

    if "FALCON_CLIENT_ID" in os.environ and "FALCON_CLIENT_SECRET" in os.environ:
        dbg_falcon_client_id = os.environ["FALCON_CLIENT_ID"]
        dbg_falcon_client_secret = os.environ["FALCON_CLIENT_SECRET"]

    global DEBUG_TOKEN, AUTH  # pylint: disable=W0603
    DEBUG_TOKEN, AUTH = startup(dbg_falcon_client_id, dbg_falcon_client_secret)
    embed()


# Move the internal python help() function to python_help()
python_help = help

# Configure our banner
BANNER = r"""
,---.     |                   ,--.      |
|__. ,---.|    ,---.,---.,---.|   |,---.|---..   .,---.
|    ,---||    |    |   ||   ||   ||---'|   ||   ||   |
`    `---^`---'`---'`---'`   '`--' `---'`---'`---'`---|
                                                  `---'
            CrowdStrike Python 3 Debug Interface

This shell-like interface allows for quick demoing and prototyping
of API operations using the CrowdStrike FalconPy SDK and Python 3.

                             |
         _____________   __ -+- _____________
         \_____     /   /_ \ |   \     _____/
           \_____   \____/  \____/    _____/
             \_____    FalconPy      _____/
               \___________  ___________/
                         /____\

           Please type help() to learn more.
"""

# Default our debug token and auth object to False
DEBUG_TOKEN = False
AUTH = False

atexit.register(exit_handler)
log = setup_logging()
import_all()
init()
