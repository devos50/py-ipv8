import os
from asyncio import ensure_future, get_event_loop, set_event_loop, sleep

from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, BootstrapperDefinition, Bootstrapper, Strategy, WalkerDefinition
from ipv8_service import IPv8
from simulation.discrete_loop import DiscreteLoop
from simulation.simulation_endpoint import SimulationEndpoint
from tracker.tracker import EndpointServer


class PingPongCommunity(Community):
    """
    This basic community sends ping messages to other known peers every two seconds.
    """
    community_id = os.urandom(20)

    def __init__(self, my_peer, endpoint, network):
        super().__init__(my_peer, endpoint, network)

    def started(self):
        self.register_task("send_ping", self.print_peers, interval=2.0, delay=0)

    def print_peers(self):
        self._logger.info("Knowing %d peers...", len(self.network.verified_peers))


async def start_communities():
    # Start the bootstrap node
    bootstrap_endpoint = SimulationEndpoint()
    await bootstrap_endpoint.open()
    bootstrap_overlay = EndpointServer(bootstrap_endpoint)
    print(bootstrap_endpoint.wan_address)

    instances = []
    for i in range(10):
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.add_key("my peer", "medium", f"ec{i}.pem")
        bootstrap_ips = [bootstrap_endpoint.wan_address]
        bootstrappers = [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper,
                                                {"ip_addresses": bootstrap_ips, "dns_addresses": []})]
        walkers = [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})]
        builder.add_overlay("PingPongCommunity", "my peer", walkers, bootstrappers, {}, [('started',)])

        endpoint = SimulationEndpoint()
        instance = IPv8(builder.finalize(), endpoint_override=endpoint,
                        extra_communities={'PingPongCommunity': PingPongCommunity})
        await instance.start()
        instances.append(instance)


async def run_simulation():
    await start_communities()
    await sleep(10)
    get_event_loop().stop()

# We use a discrete event loop to enable quick simulations.
loop = DiscreteLoop()
set_event_loop(loop)

ensure_future(run_simulation())

loop.run_forever()
