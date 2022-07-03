from enum import Enum

TORRENT_IPV4_HEADER = 20
TORRENT_IPV6_HEADER = 40
TORRENT_SOCKS5_HEADER = 6  # plus the size of the destination address
TORRENT_ETHERNET_MTU = 1500
TORRENT_UDP_HEADER = 8
TORRENT_INET_MIN_MTU = 576

MAX_MTU = 65536

UTP_HEADER_SIZE = 20


class UTPExtensionType(Enum):
    NO_EXTENSION = 0
    UTP_SACK = 1
    UTP_CLOSE_REASON = 3


def compare_less_wrap(lhs: int, rhs: int, mask: int) -> bool:
    dist_down = (lhs - rhs) & mask
    dist_up = (rhs - lhs) & mask
    return dist_up < dist_down
