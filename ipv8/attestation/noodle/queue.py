from twisted.internet.defer import Deferred


class TransferQueue(object):
    """
    This class implements a queue for blocks that are about to be created.
    """
    def __init__(self):
        self.queue = []

    def is_empty(self):
        return not self.queue

    def insert(self, target_peer, value):
        """
        Insert an item in the queue. Return a deferred if the transaction is made.
        """
        deferred = Deferred()
        self.queue.append((deferred, target_peer, value))
        return deferred

    def delete(self):
        if not self.queue:
            return None

        return self.queue.pop(0)


class BlockProcessQueue(object):
    """
    This class implements a queue for blocks that are about to be created.
    """
    def __init__(self):
        self.queue = []

    def is_empty(self):
        return not self.queue

    def insert(self, peer, block):
        """
        Insert an item in the queue. Return a deferred if the transaction is made.
        """
        self.queue.append((peer, block))

    def delete(self):
        if not self.queue:
            return None

        return self.queue.pop(0)
