import asyncio
import heapq


class DiscreteLoop(asyncio.BaseEventLoop):
    """
    A discrete asyncio loop that immediately executes incoming tasks without a real-time waiting period.
    This loop can be helpful when quickly running simulation experiments with the IPv8 library. Usage:

    loop = DiscreteLoop()
    set_event_loop(loop)
    """

    def __init__(self):
        self._time = 0
        self._running = False
        self._scheduled = []
        self._exc = None
        super().__init__()

    def get_debug(self):
        return False

    def time(self):
        return self._time

    def run_forever(self):
        self._running = True
        asyncio._set_running_loop(self)
        while (self._ready or self._scheduled) and self._running:
            self._process_events()
            if self._ready:
                h = self._ready.popleft()
            else:
                h = heapq.heappop(self._scheduled)
                self._time = h._when
                h._scheduled = False
            if not h._cancelled:
                h._run()
            if self._exc is not None:
                raise self._exc

    def run_until_complete(self, future):
        raise NotImplementedError

    def _timer_handle_cancelled(self, handle):
        pass

    def is_running(self):
        return self._running

    def is_closed(self):
        return not self._running

    def stop(self):
        self._running = False

    def close(self):
        self._running = False

    def call_exception_handler(self, context):
        self._exc = context.get('exception', None)

    def _process_events(self):
        # This method processes ready events and sets the next ready event in the '_ready' attribute.
        pass  # Your current implementation doesn't need to do anything in this method.
