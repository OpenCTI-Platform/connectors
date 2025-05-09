"""The pubsub module provides a simple publish/subscribe mechanism using asyncio queues."""

import asyncio
from typing import Any, Dict, List


class PubSubBroker:
    """A singleton class that manages a publish/subscribe mechanism using asyncio queues."""

    _instance: "PubSubBroker | None" = None

    def __init__(self) -> None:
        """Initialize the PubSubBroker instance."""
        if self._instance is not None:
            raise RuntimeError("This class is a singleton! Use the instance method.")
        self._names: Dict[str, List[asyncio.Queue[Any]]] = {}

    def __new__(cls) -> "PubSubBroker":
        """Create a singleton instance of the PubSubBroker class."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._names = {}
        return cls._instance

    def subscribe(self, name: str) -> asyncio.Queue[Any]:
        """Subscribe to a queue for receiving messages."""
        queue: asyncio.Queue[Any] = asyncio.Queue()
        self._names.setdefault(name, []).append(queue)
        return queue

    async def publish(self, name: str, message: Any) -> None:
        """Publish a message to all subscribers of a given name."""
        for q in self._names.get(name, []):
            await q.put(message)


broker = PubSubBroker()
