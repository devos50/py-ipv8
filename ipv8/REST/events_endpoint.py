import json

from twisted.web import server, resource

from ipv8.attestation.trustchain.community import TrustChainCommunity
from ..attestation.trustchain.listener import BlockListener


class EventsEndpoint(resource.Resource, BlockListener):
    """
    Important events in IPv8 are returned over the events endpoint. This connection is held open. Each event is
    pushed over this endpoint in the form of a JSON dictionary. Each JSON dictionary contains a type field that
    indicates the type of the event. Individual events are separated by a newline character (\n).

    Currently, the following events are implemented:

    - block: An indication when a new TrustChain block has been discovered.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)
        self.session = session
        self.events_requests = []

        # Register as block listener
        trustchain_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TrustChainCommunity)]
        if trustchain_overlays:
            trustchain_overlays[0].add_listener(self)

    def write_data(self, message):
        """
        Write data over the event socket if it's open.
        """
        [request.write(json.dumps(message) + '\n') for request in self.events_requests]

    def should_sign(self, block):
        return False

    def received_block(self, block):
        self.write_data({"type": "block", "event": dict(block)})

    def render_GET(self, request):
        """
        .. http:get:: /events

        A GET request to this endpoint will open the event connection.

            **Example request**:

                .. sourcecode:: none

                    curl -X GET http://localhost:8085/events
        """
        def on_request_finished(_):
            self.events_requests.remove(request)

        self.events_requests.append(request)
        request.notifyFinish().addCallbacks(on_request_finished, on_request_finished)

        request.write(json.dumps({"type": "events_start", "event": {}}) + '\n')

        return server.NOT_DONE_YET
