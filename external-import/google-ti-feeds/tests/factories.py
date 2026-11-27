"""Base class of the Pydantic model factories used by the tests."""

from typing import Generic, TypeVar

from polyfactory.factories.pydantic_factory import ModelFactory
from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)


class GTIModelFactory(ModelFactory[ModelT], Generic[ModelT]):
    """Model factory with the polyfactory settings shared by every test factory."""

    __is_base_factory__ = True
    # Polyfactory current behaviour, set explicitly: the implicit default is deprecated.
    __check_model__ = False
