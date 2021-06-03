"""
Common classes for tracker_plugin.py and tracker_reporter_plugin.py scripts
"""
import signal
import ssl
from asyncio import ensure_future, get_event_loop
from binascii import hexlify

from aiohttp import web

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401


from ipv8.REST.base_endpoint import Response
from ipv8.REST.rest_manager import ApiKeyMiddleware
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint


class TrackerService:

    def __init__(self):
        """
        Initialize the variables of the TrackerServiceMaker and the logger.
        """
        self.endpoint = None
        self.stopping = False
        self.overlay = None
        self.site = None

    def create_endpoint_server(self):
        return EndpointServer(self.endpoint)

    async def start_tracker(self, listen_port):
        """
        Main method to startup the tracker.
        """
        self.endpoint = UDPEndpoint(listen_port)
        await self.endpoint.open()
        self.overlay = self.create_endpoint_server()

        async def signal_handler(sig):
            print("Received shut down signal %s" % sig)
            if not self.stopping:
                self.stopping = True
                await self.overlay.unload()
                self.endpoint.close()
                if self.site:
                    await self.site.stop()
                get_event_loop().stop()

        signal.signal(signal.SIGINT, lambda sig, _: ensure_future(signal_handler(sig)))
        signal.signal(signal.SIGTERM, lambda sig, _: ensure_future(signal_handler(sig)))

        print("Started tracker")

    async def start_api(self, listen_port, api_key, cert_file):
        ssl_context = None
        if cert_file:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(cert_file)

        async def get_services(_):
            services = set.union(*self.overlay.network.services_per_peer.values()) \
                if self.overlay.network.services_per_peer else set()
            return Response({
                hexlify(service).decode(): [str(p) for p in self.overlay.network.get_peers_for_service(service)]
                for service in services
            })

        app = web.Application(middlewares=[ApiKeyMiddleware(api_key)])
        app.add_routes([web.get('/services', get_services)])
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        self.site = web.TCPSite(runner, '0.0.0.0', listen_port, ssl_context=ssl_context)
        await self.site.start()

        print("Started API server")
