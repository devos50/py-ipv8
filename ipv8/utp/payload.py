from datetime import datetime
from enum import Enum
from typing import Optional

from ..messaging.lazy_payload import vp_compile, VariablePayload


class UTPPacketType(Enum):
    ST_DATA = 0
    ST_FIN = 1
    ST_STATE = 2
    ST_RESET = 3
    ST_SYN = 4
    NUM_TYPES = 5


class UTPPayloadMetainfo:

    def __init__(self) -> None:
        self.send_time: Optional[datetime] = None
        self.allocated: int = 0
        self.size: int = 0
        self.header_size: int = 0
        self.num_transmissions: int = 0
        self.need_resend: bool = False
        self.mtu_probe: bool = False
        self.payload: Optional[UTPPayload] = None


@vp_compile
class UTPPayload(VariablePayload):
    msg_id = 1
    format_list = ['B', 'B', 'H', 'I', 'I', 'I', 'H', 'H', 'varlenH']
    names = ['type_ver', 'extension', 'connection_id', 'timestamp_microseconds', 'timestamp_difference_microseconds',
             'wnd_size', 'seq_nr', 'ack_nr', 'data']

    def get_type(self) -> UTPPacketType:
        return UTPPacketType(self.type_ver >> 4)

    def get_version(self) -> int:
        return self.type_ver & 0xf

    def get_payload_size(self):
        """
        Return the size of the data within the payload.
        """
        return len(self.data)
