"""
pipeline/queue.py — Bounded, Priority-Aware Async Event Queue with Metric Drop Tracking.

Designed for high-throughput pipeline ingestion:
  • Bounded buffer (default maxsize=10000).
  • High-priority threat events (e.g. DDoS, fast Port Scans) are protected.
  • When buffer capacity is exceeded, oldest LOW-priority events are evicted first.
  • Tracks real-time drop count and ingestion metrics for dashboard/monitoring.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
import logging
from typing import Any, Generic, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

PRIORITY_HIGH = 1
PRIORITY_LOW = 0

HIGH_PRIORITY_CLASSES = frozenset({"ddos", "recon_scan"})


@dataclass(slots=True)
class QueueItem(Generic[T]):
    """Wrapper holding priority metadata and data payload."""
    data: T
    priority: int  # 1 = HIGH, 0 = LOW
    timestamp: float


class PriorityEventQueue(Generic[T]):
    """Asynchronous bounded priority queue with selective eviction of low-priority events.

    Parameters
    ----------
    maxsize : int
        Maximum number of events held before eviction kicks in (default 10,000).
    """

    def __init__(self, maxsize: int = 10_000) -> None:
        self.maxsize = maxsize
        self._high_queue: deque[QueueItem[T]] = deque()
        self._low_queue: deque[QueueItem[T]] = deque()
        self._lock = asyncio.Lock()
        self._not_empty = asyncio.Event()

        # Telemetry metrics
        self.total_enqueued: int = 0
        self.total_dequeued: int = 0
        self.dropped_low_priority: int = 0
        self.dropped_high_priority: int = 0

    @property
    def qsize(self) -> int:
        return len(self._high_queue) + len(self._low_queue)

    @property
    def is_empty(self) -> bool:
        return self.qsize == 0

    @property
    def is_full(self) -> bool:
        return self.qsize >= self.maxsize

    @property
    def drop_count(self) -> int:
        return self.dropped_low_priority + self.dropped_high_priority

    async def put(self, data: T, priority: int = PRIORITY_LOW, timestamp: float = 0.0) -> bool:
        """Enqueue an event. If full, selectively evicts lowest-priority item.

        Returns True if enqueued, False if dropped.
        """
        async with self._lock:
            return self._put_unlocked(data, priority, timestamp)

    def put_nowait(self, data: T, priority: int = PRIORITY_LOW, timestamp: float = 0.0) -> bool:
        """Synchronous enqueue for fast callbacks."""
        return self._put_unlocked(data, priority, timestamp)

    def _put_unlocked(self, data: T, priority: int, timestamp: float) -> bool:
        item = QueueItem(data=data, priority=priority, timestamp=timestamp)

        if self.qsize >= self.maxsize:
            if priority == PRIORITY_HIGH:
                # Evict oldest low-priority item if available to make space
                if self._low_queue:
                    self._low_queue.popleft()
                    self.dropped_low_priority += 1
                else:
                    # All items are high priority; drop oldest high
                    self._high_queue.popleft()
                    self.dropped_high_priority += 1
            else:
                # Low priority item dropped when queue is full
                self.dropped_low_priority += 1
                if self.dropped_low_priority % 1000 == 1:
                    logger.warning(
                        "PriorityEventQueue full (%d items). Dropped low-priority event (total dropped=%d).",
                        self.maxsize,
                        self.dropped_low_priority,
                    )
                return False

        if priority == PRIORITY_HIGH:
            self._high_queue.append(item)
        else:
            self._low_queue.append(item)

        self.total_enqueued += 1
        self._not_empty.set()
        return True

    async def get(self, timeout: Optional[float] = None) -> T:
        """Retrieve the next item. High priority items are yielded before low priority."""
        async def _fetch():
            while True:
                async with self._lock:
                    if self._high_queue:
                        item = self._high_queue.popleft()
                        self.total_dequeued += 1
                        if self.qsize == 0:
                            self._not_empty.clear()
                        return item.data
                    elif self._low_queue:
                        item = self._low_queue.popleft()
                        self.total_dequeued += 1
                        if self.qsize == 0:
                            self._not_empty.clear()
                        return item.data
                    else:
                        self._not_empty.clear()

                # Wait outside the lock until new items arrive
                await self._not_empty.wait()

        if timeout is not None:
            return await asyncio.wait_for(_fetch(), timeout=timeout)
        return await _fetch()

    def signal_shutdown(self) -> None:
        """Wake up any pending get() calls during shutdown."""
        self._not_empty.set()

    def get_metrics(self) -> dict[str, Any]:
        """Return snapshot dictionary of queue performance and drop metrics."""
        return {
            "qsize": self.qsize,
            "maxsize": self.maxsize,
            "total_enqueued": self.total_enqueued,
            "total_dequeued": self.total_dequeued,
            "dropped_low_priority": self.dropped_low_priority,
            "dropped_high_priority": self.dropped_high_priority,
            "total_dropped": self.drop_count,
        }
