from random import sample
from time import time
from .discovery import DiscoveryStrategy


class RandomChurn(DiscoveryStrategy):
    """
    Select random peers, ping them if inactive, remove them if unresponsive.
    """

    def __init__(self, overlay, sample_size=8, ping_interval=10.0, inactive_time=27.5, drop_time=57.5):
        """
        Random peer removal strategy.

        :param overlay: the overlay to sample peers from
        :param sample_size: the amount of peers to check at once
        :param ping_interval: time between pings in the range of inactive_time to drop_time
        :param inactive_time: time before pings are sent to check liveness
        :param drop_time: time after which a peer is dropped
        """
        super(RandomChurn, self).__init__(overlay)
        self._pinged = {}
        self.sample_size = sample_size
        self.ping_interval = ping_interval
        self.inactive_time = inactive_time
        self.drop_time = drop_time

    def should_drop(self, peer):
        """
        Have we passed the time before we consider this peer to be unreachable.
        """
        if peer.last_response == 0:
            return False
        return time() > (peer.last_response + self.drop_time)

    def is_inactive(self, peer):
        """
        Have we passed the time before we consider this peer to be inactive.
        """
        if peer.last_response == 0:
            return False
        return time() > (peer.last_response + self.inactive_time)

    def take_step(self, service_id=None):
        """
        Select a new (set of) peer(s) to investigate liveness for.
        """
        # See if we need to clean our ping cache
        to_remove = []
        for address, timestamp in self._pinged.iteritems():
            if time() > (timestamp + self.ping_interval):
                to_remove.append(address)
        for address in to_remove:
            del self._pinged[address]
        # Find an inactive or droppable peer
        sample_size = min(len(self.overlay.network.verified_peers), self.sample_size)
        if sample_size:
            window = sample(self.overlay.network.verified_peers, sample_size)

            for peer in window:
                if self.should_drop(peer):
                    self.overlay.network.remove_peer(peer)
                elif self.is_inactive(peer):
                    if peer.address not in self._pinged:
                        self._pinged[peer.address] = time()
                        packet = self.overlay.create_ping()
                        self.overlay.endpoint.send(peer.address, packet)
