"""Collects final queue items into batches and sends them via a provided sender."""
import asyncio
from typing import Any, Callable, Coroutine, List

from connector.src.custom.pubsub import broker


class BatchCollector:
    """Collect final queue items into batches and sends them via a provided sender."""

    def __init__(
        self,
        topic: str,
        batch_size: int,
        flush_interval: float,
        send_func: Callable[[list[Any]], Coroutine[Any, Any, None]],
        sentinel_obj: Any
    ) -> None:
        """Initialize the BatchCollector.

        Args:
            topic: name of the final topic to subscribe to
            batch_size: max number of bundles per batch
            flush_interval: seconds to wait before flushing incomplete batch
            send_func: callable to process each batch
            sentinel_obj: object to signal the end of the stream

        """
        self.topic = topic
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._send_func = send_func
        self._buffer: List[Any] = []
        self._stop = asyncio.Event()
        self._sentinel_obj = sentinel_obj

    async def run(self) -> None:
        """Run the BatchCollector.

        This method subscribes to the topic, flushes the buffer periodically,
        and processes the batch when it reaches the maximum size.
        """
        queue = broker.subscribe(self.topic)
        flush_task = asyncio.create_task(self._flush_periodically())

        while True:
            item = await queue.get()
            queue.task_done()
            if item is self._sentinel_obj:
                break
            self._buffer.append(item.dict())
            if len(self._buffer) >= self.batch_size:
                await self._flush()

        await self._flush()
        self._stop.set()
        await flush_task

    async def _flush_periodically(self) -> None:
        """Flush the buffer periodically."""
        while not self._stop.is_set():
            await asyncio.sleep(self.flush_interval)
            if self._buffer:
                await self._flush()

    async def _flush(self) -> None:
        """Flush the buffer."""
        batch = self._buffer.copy()
        self._buffer.clear()
        await self._send_func(batch)
