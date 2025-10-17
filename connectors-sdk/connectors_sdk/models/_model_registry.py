from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)  # Preserve metadata when using register decorator


class _ModelRegistry:
    """Singleton registry for OpenCTI models."""

    _instance: _ModelRegistry | None = None
    _initialized: bool = False

    def __new__(cls) -> _ModelRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if _ModelRegistry._initialized:
            return
        self.models: dict[str, type[BaseModel]] = {}
        _ModelRegistry._initialized = True

    def register(self, model_class: type[T]) -> type[T]:
        """Register a model class in the registry.

        Args:
            model_class (BaseModel-like): The model class to register.

        Returns:
            BaseModel-like: The registered model class.
        """
        self.models[model_class.__name__] = model_class
        return model_class

    def rebuild_all(self) -> None:
        for model in self.models.values():
            model.model_rebuild(_types_namespace=self.models)


MODEL_REGISTRY = _ModelRegistry()
