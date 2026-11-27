"""Loading contract shared by every connector destination."""

from abc import ABC, abstractmethod

from stix2.v21 import Bundle


class AbstractLoader(ABC):
    """Deliver standard STIX 2.1 bundles to a destination.

    Contract every implementation honours:

    * ``load`` takes one STIX 2.1 bundle and returns nothing. A normal return
      means the whole bundle has been delivered to the loader's destination.
    * A bundle that cannot be delivered raises an error; ``load`` never
      returns as if it had been delivered.
    * The bundle is left unchanged.

    A loader follows the last transformer of a chain, whose output type must
    therefore be ``stix2.v21.Bundle``.
    """

    @abstractmethod
    def load(self, bundle: Bundle) -> None:
        """Deliver ``bundle`` to the loader's destination."""
