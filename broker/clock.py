"""Time seam: production code always asks a Clock for `now()` instead of
calling time.time() directly, so tests can control the passage of time
without sleeping."""
import time


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class FakeClock:
    def __init__(self, start: int = 1_700_000_000):
        self._now = start

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now += seconds
