"""Transformation contract shared by every connector stage."""

from abc import ABC, abstractmethod


class AbstractTransformer[InputType, OutputType](ABC):
    """Convert one item of ``InputType`` into one value of ``OutputType``.

    Contract every implementation honours:

    * One input item gives exactly one output value. A transformer that
      turns one item into several objects declares a collection as its
      ``OutputType``.
    * ``InputType`` and ``OutputType`` are unconstrained: the input may be an
      extractor's item type or another transformer's ``OutputType``, including
      types that are not validated models (stix2 objects, for example). A
      pipeline can chain two transformers when the first one's ``OutputType``
      matches the second one's ``InputType``.
    * An item that cannot be converted raises an error that identifies the
      item and the reason. No empty or placeholder value is returned instead.
    * The item is left unchanged.
    """

    @abstractmethod
    def convert(self, item: InputType) -> OutputType:
        """Return the conversion of ``item``."""
