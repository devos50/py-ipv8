from dataclasses import dataclass
from enum import Enum


class ProxyType(Enum):
    NONE = 0
    SOCKS5 = 1
    SOCKS5_PW = 2


@dataclass
class UTPSettings:
    proxy_type: ProxyType = ProxyType.NONE
    connections_limit: int = 200
    utp_min_timeout: int = 500
    utp_cwnd_reduce_timer: int = 100
    utp_loss_multiplier: int = 50
    utp_num_resends: int = 3
