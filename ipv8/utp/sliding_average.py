class SlidingAverage:
    """
    an exponential moving average accumulator. Add samples to it and it keeps track of a moving mean value
    and an average deviation.
    """

    def __init__(self, inverted_gain: int):
        self.inverted_gain: int = inverted_gain
        self.m_mean = 0
        self.m_average_deviation = 0
        self.m_num_samples = 0

    def add_sample(self, s: int) -> None:
        # fixed point
        s *= 64
        deviation: int = abs(self.m_mean - s) if self.m_num_samples > 0 else 0

        if self.m_num_samples < self.inverted_gain:
            self.m_num_samples += 1

        self.m_mean += (s - self.m_mean) / self.m_num_samples

        if self.m_num_samples > 1:
            # the exact same thing for deviation off the mean except -1 on the samples, because the number of deviation
            # samples always lags behind by 1 (you need to actual samples to have a single deviation sample).
            self.m_average_deviation += (deviation - self.m_average_deviation) / (self.m_num_samples - 1)

    def mean(self) -> int:
        if self.m_num_samples > 0:
            return (self.m_mean + 32) // 64
        return 0

    def avg_deviation(self) -> int:
        if self.m_num_samples > 1:
            return (self.m_average_deviation + 32) // 64
        return 0
