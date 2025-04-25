import abc

from pydantic import BaseModel


class BaseClient(BaseModel, abc.ABC):
    """Base class for all clients."""
