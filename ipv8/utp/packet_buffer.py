from typing import Dict, Optional

from ipv8.utp.payload import UTPPayloadMetainfo


class PacketBuffer:

    def __init__(self):
        self.buffer: Dict[int, UTPPayloadMetainfo] = {}

    def insert(self, idx: int, payload: UTPPayloadMetainfo) -> UTPPayloadMetainfo:
        self.buffer[idx] = payload
        return payload

    def remove(self, idx: int) -> Optional[UTPPayloadMetainfo]:
        return self.buffer.pop(idx, None)

    def at(self, idx: int) -> Optional[UTPPayloadMetainfo]:
        return self.buffer.get(idx, None)

    def size(self) -> int:
        return len(self.buffer)

    def empty(self) -> bool:
        return self.size() == 0
