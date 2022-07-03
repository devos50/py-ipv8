from typing import List

from ..utp import compare_less_wrap


class TimestampHistory:
    """
    timestamp history keeps a history of the lowest timestamps we've seen in the last 20 minutes.
    """
    NOT_INITIALIZED = 0xFFFF
    TIME_MASK = 0xFFFFFFFF

    def __init__(self) -> None:
        self.m_history: List[int] = []
        self.m_base: int = 0
        self.m_index: int = 0
        self.m_num_samples = self.NOT_INITIALIZED
        self.history_size = 20

    def base(self):
        assert self.initialized()
        return self.m_base

    def initialized(self) -> bool:
        return self.m_num_samples != self.NOT_INITIALIZED

    def add_sample(self, sample: int, step: bool) -> int:
        if not self.initialized():
            self.m_history = [sample] * self.history_size
            self.m_base = sample
            self.m_num_samples = 0

        # Don't let the counter wrap
        if self.m_num_samples < 0xFFFE:
            self.m_num_samples += 1

        # if sample is less than base, update the base and update the history entry (because it will be less than
        # that too)
        if compare_less_wrap(sample, self.m_base, self.TIME_MASK):
            self.m_base = sample
            self.m_history[self.m_index] = sample

        # if sample is less than our history entry, update it
        elif compare_less_wrap(sample, self.m_history[self.m_index], self.TIME_MASK):
            self.m_history[self.m_index] = sample

        ret: int = sample - self.m_base

        # don't step base delay history unless we have at least 120 samples. Anything less would suggest that the
        # connection is essentially idle and the samples are probably not very reliable
        if step and self.m_num_samples > 120:
            self.m_num_samples = 0
            self.m_index = (self.m_index + 1) % self.history_size

            self.m_history[self.m_index] = sample
            self.m_base = sample
            for h in self.m_history:
                if compare_less_wrap(h, self.m_base, self.TIME_MASK):
                    self.m_base = h

        return ret

    def adjust_base(self, change: int) -> None:
        assert self.initialized()
        self.m_base += change
        # make sure this adjustment sticks by updating all history slots
        for ind, h in enumerate(self.m_history):
            if compare_less_wrap(h, self.m_base, self.TIME_MASK):
                self.m_history[ind] = self.m_base
