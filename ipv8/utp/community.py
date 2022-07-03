from binascii import unhexlify
from datetime import datetime

from .payload import UTPPayload
from .settings import UTPSettings
from .utp_socket_manager import UTPSocketManager
from ..community import Community
from ..lazy_community import lazy_wrapper
from ..types import Peer


class UTPCommunity(Community):
    community_id = unhexlify('d5889074c1e4c60423ddb6eab07ba0ca5695ead7')

    def __init__(self, *args, **kwargs):
        settings = kwargs.pop("settings") if "settings" in kwargs else UTPSettings()
        super().__init__(*args, **kwargs)
        self.utp_socket_manager = UTPSocketManager(settings, self)

        self.add_message_handler(UTPPayload, self.on_utp_payload)

    @lazy_wrapper(UTPPayload)
    def on_utp_payload(self, peer: Peer, payload: UTPPayload) -> bool:
        receive_time = datetime.now()
        return self.utp_socket_manager.incoming_packet(payload, peer, receive_time)
