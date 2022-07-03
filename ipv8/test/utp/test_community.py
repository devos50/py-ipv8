from ..mocking.ipv8 import MockIPv8
from ...test.base import TestBase
from ...utp.community import UTPCommunity


class TestUTPCommunity(TestBase):
    NUM_NODES = 2

    def create_node(self, *args, **kwargs):
        return MockIPv8("curve25519", self.overlay_class, *args, **kwargs)

    def setUp(self):
        super().setUp()
        self.batch_size = 1

        self.initialize(UTPCommunity, self.NUM_NODES)

    def test_connect(self):
        """
        Test opening a UTP connection to another peer.
        """
        socket = self.nodes[0].overlay.utp_socket_manager.new_utp_socket()
        socket.do_connect(self.nodes[1].overlay.endpoint.get_address())
