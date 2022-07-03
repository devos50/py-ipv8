import random
from datetime import datetime
from typing import List, Dict

from . import TORRENT_ETHERNET_MTU, TORRENT_UDP_HEADER, TORRENT_IPV4_HEADER, TORRENT_SOCKS5_HEADER, TORRENT_IPV6_HEADER, \
    MAX_MTU
from .payload import UTPPayload, UTPPacketType
from .settings import UTPSettings, ProxyType
from .utp_socket import UTPSocket
from ..messaging.interfaces.udp.endpoint import UDPv4Address
from ..types import Address, Community, Endpoint, Peer


class UTPSocketManager:

    def __init__(self, settings: UTPSettings, community: Community):
        self.settings: UTPSettings = settings
        self.community = community
        self.endpoint: Endpoint = self.community.endpoint

        self.m_restrict_mtu: List[int] = [MAX_MTU, MAX_MTU, MAX_MTU]

        self.m_utp_sockets: Dict[int, UTPSocket] = {}

        self.m_new_connection: int = -1

    def incoming_packet(self, payload: UTPPayload, peer: Peer, receive_time: datetime) -> bool:
        if payload.get_version() != 1:
            return False

        if payload.connection_id in self.m_utp_sockets:
            self.m_utp_sockets[payload.connection_id].incoming_packet(payload, peer, receive_time)
        else:
            # if not found, see if it's a SYN packet, if it is, create a new socket
            if payload.get_type() == UTPPacketType.ST_SYN:
                # possible SYN flood. Just ignore
                if self.num_sockets() > self.settings.connections_limit * 2:
                    return False

                assert self.m_new_connection == -1
                self.m_new_connection = payload.connection_id
                socket = self.new_utp_socket()
                mtu = self.mtu_for_dest(peer.address)
                socket.init_mtu(mtu)
                return socket.incoming_packet(payload, peer, receive_time)
            elif payload.get_type() == UTPPacketType.ST_RESET:
                return False

            return False

    def mtu_for_dest(self, address: Address) -> int:
        # TODO add teredo support
        mtu: int = TORRENT_ETHERNET_MTU - TORRENT_UDP_HEADER
        if self.settings.proxy_type == ProxyType.SOCKS5 or self.settings.proxy_type == ProxyType.SOCKS5_PW:
            # this is for the IP layer
            # assume the proxy is running over IPv4
            mtu -= TORRENT_IPV4_HEADER

            # this is for the SOCKS layer
            mtu -= TORRENT_SOCKS5_HEADER

            # the address field in the SOCKS header
            if isinstance(address, UDPv4Address):
                mtu -= 4
            else:
                mtu -= 16
        else:
            if isinstance(address, UDPv4Address):
                mtu -= TORRENT_IPV4_HEADER
            else:
                mtu -= TORRENT_IPV6_HEADER

        return min(mtu, self.restrict_mtu())

    def num_sockets(self) -> int:
        return len(self.m_utp_sockets)

    def min_timeout(self) -> int:
        return self.settings.utp_min_timeout

    def cwnd_reduce_timer(self) -> int:
        return self.settings.utp_cwnd_reduce_timer

    def loss_multiplier(self) -> int:
        return self.settings.utp_loss_multiplier

    def num_resends(self) -> int:
        return self.settings.utp_num_resends

    def restrict_mtu(self) -> int:
        return max(self.m_restrict_mtu)

    def new_utp_socket(self) -> UTPSocket:
        if self.m_new_connection != -1:
            send_id = self.m_new_connection
            recv_id = self.m_new_connection + 1
            self.m_new_connection = -1
        else:
            send_id = random.randint(0, 0xFFFF)
            recv_id = send_id - 1

        socket = UTPSocket(recv_id, send_id, self)
        self.m_utp_sockets[recv_id] = socket
        return socket
