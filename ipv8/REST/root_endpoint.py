from __future__ import absolute_import

from .attestation_endpoint import AttestationEndpoint
from .base_endpoint import BaseEndpoint
from .crawl_endpoint import CrawlEndpoint
from .dht_endpoint import DHTEndpoint
from .isolation_endpoint import IsolationEndpoint
from .events_endpoint import EventsEndpoint
from .network_endpoint import NetworkEndpoint
from .noblock_dht_endpoint import NoBlockDHTEndpoint
from .overlays_endpoint import OverlaysEndpoint
from .trustchain_endpoint import TrustchainEndpoint
from .tunnel_endpoint import TunnelEndpoint


class RootEndpoint(BaseEndpoint):
    """
    The root endpoint of the HTTP API is the root resource in the request tree.
    It will dispatch requests regarding torrents, channels, settings etc to the right child endpoint.
    """

    def __init__(self, session):
        """
        During the initialization of the REST API, we only start the event sockets and the state endpoint.
        We enable the other endpoints after completing the starting procedure.
        """
        super(RootEndpoint, self).__init__()
        self.session = session
        self.putChild(b'attestation', AttestationEndpoint(session))
        self.putChild(b'dht', DHTEndpoint(session))
        self.putChild(b'isolation', IsolationEndpoint(session))
        self.putChild(b'network', NetworkEndpoint(session))
        self.putChild(b'noblockdht', NoBlockDHTEndpoint(session))
        self.putChild(b'overlays', OverlaysEndpoint(session))
        self.putChild(b'trustchain', TrustchainEndpoint(session))
        self.putChild(b'tunnel', TunnelEndpoint(session))
        self.putChild(b'events', EventsEndpoint(session))
        self.putChild(b'crawl', CrawlEndpoint(session))
