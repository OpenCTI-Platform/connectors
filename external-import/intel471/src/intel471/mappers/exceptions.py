class TitanStixException(Exception):
    pass


class StixMapperNotFound(TitanStixException):
    pass


class EmptyBundle(TitanStixException):
    pass
