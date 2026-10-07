from collections.abc import Callable
from typing import TYPE_CHECKING

from pydantic import ValidationError

if TYPE_CHECKING:
    from spycloud_connector.services.converter_to_stix import ConverterToStix


def handle_pydantic_validation_error(decorated_function: Callable):
    """
    Handle Pydantic's ValidationErrors during models instanciation.
    :param decorated_function: A ConverterToStix instance method instanciating a Pydantic model.
    :return: Decorator
    """

    def decorator(self: "ConverterToStix", *args, **kwargs):
        try:
            return decorated_function(self, *args, **kwargs)
        except ValidationError as e:
            self.helper.connector_logger.error(str(e))
            return None

    return decorator
