import json
import os
import time

from ipv8.peerdiscovery.deprecated.discovery import DiscoveryCommunity
from ipv8.keyvault.crypto import ECCrypto
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
from ipv8.peerdiscovery.discovery import RandomWalk
from ipv8.peerdiscovery.churn import RandomChurn
from ipv8.peerdiscovery.network import Network
from ipv8.peer import Peer

from geoip import geolite2
from twisted.internet.task import LoopingCall


class IPV8(object):

    def __init__(self):
        self.endpoint = UDPEndpoint(8090)
        self.endpoint.open()

        self.network = Network()

        self.my_peer = Peer(ECCrypto().generate_key(u"very-low"))

        self.discovery_overlay = DiscoveryCommunity(self.my_peer, self.endpoint, self.network)
        self.discovery_strategy = RandomWalk(self.discovery_overlay)
        self.discovery_churn_strategy = RandomChurn(self.discovery_overlay)

        self.state_machine_lc = LoopingCall(self.on_tick).start(0.05, False)
        self.last_peer_write = time.time()

    def on_tick(self):
        if self.endpoint.is_open():
            if not self.discovery_overlay.network.get_walkable_addresses():
                self.discovery_overlay.bootstrap()
            else:
                self.discovery_strategy.take_step()
                self.discovery_churn_strategy.take_step()
            if time.time() > self.last_peer_write + 10:
                services_dict = {}
                countries_dict = {}
                for p in self.network.verified_peers:
                    # Try a geo lookup, list country as '?' if we have no info
                    data = geolite2.lookup(p.address[0])
                    if data:
                        countries_dict[data.country] = 1 + countries_dict.get(data.country, 0)
                    else:
                        countries_dict['?'] = 1 + countries_dict.get('?', 0)
                    # List the advertised services per peer (note that these may include personal channels)
                    for cid in self.network.get_services_for_peer(p):
                        hcid = cid.encode('hex')
                        services_dict[hcid] = 1 + services_dict.get(hcid, 0)
                with open("peer_info.json", "w") as f:
                    print >> f, json.dumps({"services": services_dict, "countries": countries_dict})
                with open("peer_count.txt", "w") as f:
                    print >> f, len(self.network.verified_peers)
                self.last_peer_write = time.time()

if __name__ == '__main__':
    from twisted.internet import reactor
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger()
    logger.propagate = False
    from twisted.python import log
    observer = log.PythonLoggingObserver(loggerName=logger.name)
    observer.start()

    ipv8 = IPV8()

    reactor.run()
