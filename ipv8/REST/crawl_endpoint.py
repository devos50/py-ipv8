import json

from twisted.web import http
from twisted.web import resource

from ipv8.peer import Peer
from ..attestation.trustchain.community import TrustChainCommunity


class CrawlEndpoint(resource.Resource):
    """
    This endpoint is responsible for crawling other peers.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)

        trustchain_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TrustChainCommunity)]
        if trustchain_overlays:
            self.trustchain = trustchain_overlays[0]

    def render_POST(self, request):
        """
        Send a crawl request to a specific peer.
        """
        req_params = ['address', 'port', 'start', 'stop', 'pub_key']

        for req_param in req_params:
            if req_param not in request.args:
                request.setResponseCode(http.BAD_REQUEST)
                return json.dumps({"error": "%s not in parameters" % req_param})

        pub_key = request.args['pub_key'][0].decode('hex')
        peer = Peer(pub_key, address=(request.args['address'][0], int(request.args['port'][0])))
        start = int(request.args['start'][0])
        stop = int(request.args['stop'][0])

        self.trustchain.send_crawl_request(peer, pub_key, start_seq_num=start, end_seq_num=stop)

        return json.dumps({"crawl": "ok"})
