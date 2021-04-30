import logging

TRACE_LOG_LEVEL = 5
logging.addLevelName(TRACE_LOG_LEVEL, "TRACE")


def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LOG_LEVEL):
        self._log(TRACE_LOG_LEVEL, message, args, **kws)


logging.Logger.trace = trace


def setup_logger(verbosity: int = 30, name: str = None) -> None:
    # # XXX: This would allow to provide an optional JSON output, which is handy in the cloud
    # supported_keys = [
    #     "asctime",
    #     "filename",
    #     "funcName",
    #     "levelname",
    #     "lineno",
    #     "module",
    #     "message",
    #     "name",
    #     "process",
    #     "processName",
    #     "thread",
    #     "threadName",
    # ]

    # def get_log_format(log_keys):
    #     return " ".join(["%({0:s})s".format(i) for i in log_keys])
    # logger.handlers.clear()
    # logHandler = logging.StreamHandler()
    # custom_format = get_log_format(supported_keys)
    # formatter = jsonlogger.JsonFormatter(custom_format)
    # logHandler.setFormatter(formatter)
    # logger.addHandler(logHandler)

    logger = logging.getLogger(name=name)

    if verbosity < 20:
        FORMAT = "[%(asctime)s.%(msecs)03d][%(filename)20s:%(lineno)-4s][ %(funcName)20s() ][%(levelname)s] %(message)s"
    else:
        FORMAT = "[%(asctime)s.%(msecs)03d][%(levelname)s] %(message)s"

    logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")

    logger.setLevel(verbosity)
