import logging
import re
from datetime import timedelta

TRACE_LOG_LEVEL = 5


def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LOG_LEVEL):
        self._log(TRACE_LOG_LEVEL, message, args, **kws)


logging.addLevelName(TRACE_LOG_LEVEL, "TRACE")
logging.Logger.trace = trace


def setup_logger(verbosity: int = 30, name: str = None) -> None:
    # TODO: It'd be great to handle an optional JSON output
    logger = logging.getLogger(name=name)

    if verbosity < 20:
        FORMAT = "[%(asctime)s.%(msecs)03d][%(filename)20s:%(lineno)-4s][%(threadName)s][ %(funcName)20s() ][%(levelname)s] %(message)s"
    else:
        FORMAT = "[%(asctime)s.%(msecs)03d][%(levelname)s] %(message)s"

    logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")
    logger.setLevel(verbosity)


# Elastic supports Months and Years, but `timedelta` does not, so skipping
# TODO: Checkout extending https://github.com/nickmaccarthy/python-datemath
RE_ELASTIC_INTERVALS = re.compile(
    r"((?P<weeks>\d+?)w)?((?P<days>\d+?)d)?((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?"
)


def parse_duration(time_str):
    parts = RE_ELASTIC_INTERVALS.match(time_str)
    if not parts:
        return
    parts = parts.groupdict()
    time_params = {}
    for name, param in parts.items():
        if param:
            time_params[name] = int(param)
    return timedelta(**time_params)


def dict_merge(dct, merge_dct, add_keys=True):
    """Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.

    This version will return a copy of the dictionary and leave the original
    arguments untouched.

    The optional argument ``add_keys``, determines whether keys which are
    present in ``merge_dict`` but not ``dct`` should be included in the
    new dict.

    Args:
        dct (dict) onto which the merge is executed
        merge_dct (dict): dct merged into dct
        add_keys (bool): whether to add new keys

    Returns:
        dict: updated dict

    Source: https://gist.github.com/angstwad/bf22d1822c38a92ec0a9#gistcomment-2622319
    """
    from collections.abc import Mapping

    dct = dct.copy()
    if not add_keys:
        merge_dct = {k: merge_dct[k] for k in set(dct).intersection(set(merge_dct))}

    for k, v in merge_dct.items():
        if k in dct and isinstance(dct[k], dict) and isinstance(merge_dct[k], Mapping):
            dct[k] = dict_merge(dct[k], merge_dct[k], add_keys=add_keys)
        else:
            dct[k] = merge_dct[k]

    return dct


def add_branch(tree, vector, value):
    """Recursively update dictionary given a vector containing the path of
    the branch. Useful for directly adding a value at a specified key path.

    Source: https://stackoverflow.com/a/59634887/6654930
    """
    key = vector[0]
    if len(vector) == 1:
        tree[key] = value
    else:
        tree[key] = add_branch(tree[key] if key in tree else {}, vector[1:], value)
    return tree


def remove_nones(d: dict):
    """
    Recurses through dictionary and removes keys with None values,
    empty strings, empty lists, and empty dicts
    """
    _clean: dict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            d2 = remove_nones(v)
            if len(d2) > 0:
                _clean[k] = d2
        elif isinstance(v, list):
            l2 = []
            for item in v:
                if item:
                    l2.append(item)
            if len(l2) > 0:
                _clean[k] = l2
        elif (v is not None) and (v != ""):
            _clean[k] = v

    return _clean
