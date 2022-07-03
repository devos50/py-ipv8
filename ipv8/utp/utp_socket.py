import logging
import random
import datetime
from enum import Enum
from typing import Optional, List

from . import TORRENT_ETHERNET_MTU, TORRENT_IPV4_HEADER, TORRENT_UDP_HEADER, TORRENT_INET_MIN_MTU, UTP_HEADER_SIZE, \
    UTPExtensionType, compare_less_wrap
from .error import UTPError, UTPErrorCode
from .packet_buffer import PacketBuffer
from .payload import UTPPayloadMetainfo, UTPPayload, UTPPacketType
from .sliding_average import SlidingAverage
from .timestamp_history import TimestampHistory
from ..types import Address, Endpoint, Peer


class UTPSocketState(Enum):
    # not yet connected
    NONE = 0

    # sent a syn packet, not received any acks
    SYN_SENT = 1

    # syn-ack received and in normal operation of sending and receiving data
    CONNECTED = 2

    # fin sent, but all packets up to the fin packet have not yet been acked. We might still be waiting for a FIN from
    # the other end
    FIN_SENT = 3

    # ====== states beyond this point =====
    # === are considered closing states ===
    # === and will cause the socket to ====
    # ============ be deleted =============

    # the socket has been gracefully disconnected and is waiting for the client to make a socket call so that we can
    # communicate this fact and actually delete all the state, or there is an error on this socket and we're
    # waiting to communicate this to the client in a callback. The error in either case is stored in m_error.
    # If the socket has gracefully shut down, the error is error::eof.
    ERROR_WAIT = 4

    # there are no more references to this socket and we can delete it
    DELETING = 5


ACK_MASK = 0xffff
dup_ack_limit = 3


class UTPSocket:

    def __init__(self, recv_id: int, send_id, socket_manager: "UTPSocketManager"):
        assert recv_id == ((send_id + 1) & 0xffff) or send_id == ((recv_id + 1) & 0xffff)

        self.logger = logging.getLogger(self.__class__.__name__)
        self.socket_manager = socket_manager

        # userdata pointer passed along with any callback. This is initialized to nullptr then set to point to the
        # utp_stream when hooked up, and then reset to 0 once the utp_stream detaches. This is used to know whether
        # or not the socket impl is still attached to a utp_stream object. When it isn't, we'll never be able to
        # signal anything back to the client, and in case of errors, we just have to delete ourselves i.e. transition
        # to the state_t::deleting state
        self.m_userdata: Optional[UTPSocket] = None

        # this is the error on this socket. If m_state is set to state_t::error_wait, this error should be
        # forwarded to the client as soon as we have a new async operation initiated
        self.m_error: Optional[UTPError] = None

        # these indicate whether or not there is an outstanding read/write or connect operation. i.e. is there upper
        # layer subscribed to these events.
        self.m_read_handler: bool = False
        self.m_write_handler: bool = False
        self.m_connect_handler: bool = False

        # the address of the remote endpoint
        self.m_remote_address: Optional[Address] = None

        # the send and receive buffers
        self.m_inbuf: PacketBuffer = PacketBuffer()
        self.m_outbuf: PacketBuffer = PacketBuffer()

        # the time when the last packet we sent times out. Including re-sends.
        # if we ever end up not having sent anything in one second (or one mean rtt + 2 average deviations,
        # whichever is greater) we set our cwnd to 1 MSS. This condition can happen either because a packet has
        # timed out and needs to be resent or because our cwnd is set to less than one MSS during congestion control.
        # it can also happen if the other end sends an advertised window size less than one MSS.
        self.m_timeout: Optional[datetime.datetime] = None

        # the last time we stepped the timestamp history
        self.m_last_history_step: datetime = datetime.datetime.now()

        # the next time we allow a lost packet to halve cwnd. We only do this once every 100ms
        self.m_next_loss: Optional[datetime.datetime] = None

        # the max number of bytes in-flight. This is a fixed point value, to get the true number of bytes, shift right
        # 16 bits the value is always >= 0, but the calculations performed on it in do_ledbat() are signed.
        self.m_cwnd: int = TORRENT_ETHERNET_MTU << 16

        self.m_delay_hist: TimestampHistory = TimestampHistory()
        self.m_their_delay_hist: TimestampHistory = TimestampHistory()

        # the slow-start threshold. This is the congestion window size (m_cwnd) in bytes the last time we left
        # slow-start mode. This is used as a threshold to leave slow-start earlier next time, to avoid packet-loss
        self.m_ssthres: int = 0

        # the timestamp diff in the last packet received, this is what we'll send back
        self.m_reply_micro: int = 0

        # this is the advertised receive window the other end sent we'll never have more un-acked bytes in flight
        # if this ever gets set to zero, we'll try one packet every second until the window opens up again
        self.m_adv_wnd: int = TORRENT_ETHERNET_MTU

        # the number of un-acked bytes we have sent
        self.m_bytes_in_flight: int = 0

        # max number of bytes to allocate for receive buffer
        self.m_receive_buffer_capacity = 1024 * 1024

        # this holds the 3 last delay measurements, these are the actual corrected delay measurements.
        # the lowest of the 3 last ones is used in the congestion controller. This is to not completely close the cwnd
        # by a single outlier.
        self.m_delay_sample_hist: List[int] = [2**32 - 1]

        # counters
        self.m_in_packets = 0
        self.m_out_packets = 0

        # average RTT
        self.m_rtt: SlidingAverage = SlidingAverage(16)

        # IPv8 endpoint
        self.endpoint: Optional[Endpoint] = None

        self.m_send_id = send_id
        self.m_recv_id = recv_id

        # this is the ack we're sending back. We have received all packets up to this sequence number
        self.m_ack_nr: int = 0

        # the sequence number of the next packet we'll send
        self.m_seq_nr: int = 0

        # this is the sequence number of the packet that everything has been ACKed up to. Everything we've
        # sent up to this point has been received by the other end.
        self.m_acked_seq_nr: int = 0

        # each packet gets one chance of "fast resend". i.e. if we have multiple duplicate acks, we may send a
        # packet immediately, if m_fast_resend_seq_nr is set to that packet's sequence number
        self.m_fast_resend_seq_nr: int = 0

        # this is the sequence number of the FIN packet we've received. This sequence number is only
        # valid if m_eof is true. We should not accept any packets beyond this sequence number from the other end
        self.m_eof_seq_nr: int = 0

        # this is the lowest sequence number that, when lost, will cause the window size to be cut in half
        self.m_loss_seq_nr: int = 0

        # the max number of bytes we can send in a packet including the header
        self.m_mtu: int = TORRENT_ETHERNET_MTU - TORRENT_IPV4_HEADER - TORRENT_UDP_HEADER - 8 - 24 - 36

        # the floor is the largest packet that we have been able to get through without fragmentation
        self.m_mtu_floor: int = TORRENT_INET_MIN_MTU - TORRENT_IPV4_HEADER - TORRENT_UDP_HEADER

        # the ceiling is the largest packet that we might be able to get through without fragmentation.
        # i.e. ceiling +1 is very likely to not get through or we have in fact experienced a drop or ICMP
        # message indicating that it is.
        self.m_mtu_ceiling: int = TORRENT_ETHERNET_MTU - TORRENT_IPV4_HEADER - TORRENT_UDP_HEADER

        # the sequence number of the probe in-flight, this is 0 if there is no probe in flight
        self.m_mtu_seq: int = 0

        # this is a counter of how many times the current m_acked_seq_nr has been ACKed. If it's ACKed more than 3
        # times, we assume the packet with the next sequence number has been lost, and we trigger
        # a re-send. Obviously an ACK only counts as a duplicate as long as we have outstanding packets following it.
        self.m_duplicate_acks: int = 0

        # the number of packet timeouts we've seen in a row
        # this affects the packet timeout time
        self.m_num_timeouts: int = 0

        # this is the cursor into m_delay_sample_hist
        self.m_delay_sample_idx: int = 0

        # the state the socket is in
        self.m_state: UTPSocketState = UTPSocketState.NONE

        # this is set to true when we receive a fin
        self.m_eof: bool = False

        # this is true while the socket is in slow start mode. It's only in slow-start during the start-up phase.
        # Slow start (contrary to what its name suggest) means that we're growing the congestion window (cwnd)
        # exponentially rather than linearly. this is done at startup of a socket in order to find its
        # link capacity faster. This behaves similar to TCP slow start.
        self.m_slow_start: bool = False

        # this is true as long as we have as many packets in flight as allowed by the congestion window (cwnd)
        self.m_cwnd_full = False

    def cancel_handlers(self, error: UTPError, shutdown: bool):
        assert error

        ret: bool = self.m_read_handler or self.m_write_handler or self.m_connect_handler

        # calling the callbacks with m_userdata being 0 will just crash
        assert (ret and self.m_userdata) or not ret

        read: bool = self.m_read_handler
        write: bool = self.m_write_handler
        connect: bool = self.m_connect_handler
        self.m_read_handler = False
        self.m_write_handler = False
        self.m_connect_handler = False

        if read:
            self.on_read(self.m_userdata, 0, error, shutdown)
        if write:
            self.on_write(self.m_userdata, 0, error, shutdown)
        if connect:
            self.on_connect(self.m_userdata, 0, error, shutdown)
        return ret

    def test_socket_state(self) -> bool:
        # if the socket is in a state where it's dead, just waiting to tell the client that it's closed. Do that and
        # transition into the deleted state, where it will be deleted it might be possible to get here twice, in which
        # we need to cancel any new handlers as well, even though we're already in the delete state
        if self.m_error is None:
            return False

        assert self.m_state in [UTPSocketState.ERROR_WAIT, UTPSocketState.DELETING]

        self.logger.debug("state: %s, error: %s", self.m_state, self.m_error.message)

        if self.cancel_handlers(self.m_error, True):
            self.m_state = UTPSocketState.DELETING
            self.logger.debug("state: %s", self.m_state)
            return True
        return False

    def init_mtu(self, mtu: int):
        # set the ceiling to what we found out from the interface
        self.m_mtu_ceiling = mtu

        # start in the middle of the PMTU search space
        self.m_mtu = (self.m_mtu_ceiling + self.m_mtu_floor) / 2
        if self.m_mtu > self.m_mtu_ceiling:
            self.m_mtu = self.m_mtu_ceiling
        if self.m_mtu_floor > mtu:
            self.m_mtu_floor = mtu

        # if the window size is smaller than one packet size set it to one
        if (self.m_cwnd >> 16) < self.m_mtu:
            self.m_cwnd = self.m_mtu * (1 << 16)

        self.logger.debug("Initializing MTU to: %d [%d, %d]", self.m_mtu, self.m_mtu_floor, self.m_mtu_ceiling)

    def send_syn(self):
        self.m_seq_nr = random.randint(0, 0xffff)
        self.m_acked_seq_nr = (self.m_seq_nr - 1) & ACK_MASK
        self.m_loss_seq_nr = self.m_acked_seq_nr
        self.m_ack_nr = 0
        self.m_fast_resend_seq_nr = self.m_seq_nr

        payload_info = UTPPayloadMetainfo()
        payload_info.size = UTP_HEADER_SIZE
        payload_info.header_size = UTP_HEADER_SIZE
        payload_info.num_transmissions = 0
        payload_info.mtu_probe = False
        payload_info.need_resend = False
        payload_info.send_time = datetime.datetime.now()

        type_ver = (UTPPacketType.ST_SYN.value << 4) | 1
        extension = UTPExtensionType.NO_EXTENSION
        timestamp_microseconds = int((payload_info.send_time - datetime.datetime(1970, 1, 1)).total_seconds() * 1000000) & 0xFFFFFFFF
        payload = UTPPayload(type_ver, extension.value, self.m_recv_id, timestamp_microseconds, self.m_reply_micro, 0, self.m_seq_nr, 0, b"")

        payload_info.payload = payload

        self.logger.debug("send_syn seq_nr:%d id: %d target:%s", self.m_seq_nr, self.m_recv_id, self.endpoint)

        # Serialize and send the packet
        packet = self.socket_manager.community.ezr_pack(UTPPayload.msg_id, payload)
        self.socket_manager.endpoint.send(self.m_remote_address, packet)

    def do_connect(self, address: Address):
        mtu: int = self.socket_manager.mtu_for_dest(address)
        self.init_mtu(mtu)
        assert not self.m_connect_handler
        self.m_remote_address = address
        self.m_connect_handler = True
        if self.test_socket_state():
            return
        self.send_syn()

    def packet_timeout(self) -> int:
        """
        Returns the number of milliseconds a packet would have before it would time-out if it was sent right now.
        Takes the RTT estimate into account.
        """

        # SYN packets have a bit longer timeout, since we don't have an RTT estimate yet, make a conservative guess
        if self.m_state == UTPSocketState.NONE:
            return 3000

        # avoid overflow by simply capping based on number of timeouts as well
        if self.m_num_timeouts >= 7:
            return 60000

        timeout: int = max(self.socket_manager.min_timeout(), self.m_rtt.mean() + self.m_rtt.avg_deviation() * 2)
        if self.m_num_timeouts > 0:
            timeout += (1 << (self.m_num_timeouts - 1)) * 1000

        # Timeouts over 1 minute are capped
        if timeout > 60000:
            timeout = 60000
        return timeout

    def update_mtu_limits(self):
        if self.m_mtu_floor > self.m_mtu_ceiling:
            # this is the case where we drop an MTU probe once we're in steady
            # state. Assume the probe was lost by chance, and don't decrement the
            # ceiling. We're still restarting the Path MTU discovery, so if the MTU
            # did in fact chance, we'll be notified again, when not in steady state.
            self.m_mtu_ceiling = self.m_mtu_floor

            # the path MTU may have changed. Perform another search dont' start all the way from start, just half
            # way down.
            self.m_mtu_floor = ((TORRENT_INET_MIN_MTU - TORRENT_IPV4_HEADER - TORRENT_UDP_HEADER) + self.m_mtu_ceiling) / 2
            self.logger.debug("reducing MTU floor")

        self.m_mtu = (self.m_mtu_floor + self.m_mtu_ceiling) / 2

        if (self.m_cwnd >> 16) < self.m_mtu:
            self.m_cwnd = self.m_mtu * (1 << 16)

        self.logger.debug("updating MTU to: %d [%d, %d]", self.m_mtu, self.m_mtu_floor, self.m_mtu_ceiling)

        # clear the mtu probe sequence number since it was either dropped or acked
        self.m_mtu_seq = 0

    def experienced_loss(self, seq_nr: int, now: datetime.datetime):
        # the window size could go below one MMS here, if it does, we'll get a timeout in about one second

        # since loss often comes in bursts, we only cut the window in half once per RTT. This is implemented by
        # limiting which packets can cause us to cut the window size. The first packet that's lost will update the
        # limit to the last sequence number we sent. i.e. only packet sent after this loss can cause another
        # window size cut. The +1 is to turn the comparison into less than or equal to. If we experience loss of the
        # same packet again, ignore it.
        if compare_less_wrap(seq_nr, self.m_loss_seq_nr + 1, ACK_MASK):
            return

        # don't reduce cwnd more than once every 100ms
        if self.m_next_loss and self.m_next_loss >= now:
            return

        self.m_next_loss = now + datetime.timedelta(milliseconds=self.socket_manager.cwnd_reduce_timer())

        # cut window size in 2
        self.m_cwnd = max(self.m_cwnd * self.socket_manager.loss_multiplier() / 100, self.m_mtu * (1 << 16))
        self.m_loss_seq_nr = self.m_seq_nr
        self.logger.debug("Lost packet %d caused cwnd cut. m_loss_seq_nr:%d", seq_nr, self.m_seq_nr)

        # if we happen to be in slow-start mode, we need to leave it
        # note that we set ssthres to the window size _after_ reducing it. Next slow start should end before we over
        # shoot.
        if self.m_slow_start:
            self.m_ssthres = self.m_cwnd >> 16
            self.m_slow_start = False
            self.logger.debug("experienced loss, slow_start -> 0 ssthres:%d", self.m_ssthres)

    def resend_packet(self, p: UTPPayloadMetainfo, fast_resend: bool) -> bool:
        # for fast re-sends the packet hasn't been marked as needing resending
        assert p.need_resend or fast_resend

        if self.m_error:
            return False

        if ((self.m_acked_seq_nr + 1) & ACK_MASK) == self.m_mtu_seq and self.m_mtu_seq != 0:
            self.m_mtu_seq = 0
            p.mtu_probe = False
            # we got multiple acks for the packet before our probe, assume it was dropped because it was too big
            self.m_mtu_ceiling = p.size - 1
            self.update_mtu_limits()

        # we can only resend the packet if there's enough space in our congestion window
        # since we can't re-packetize, some packets that are larger than the congestion window must be allowed through
        # but only if we don't have any outstanding bytes
        window_size_left: int = min(self.m_cwnd >> 16, self.m_adv_wnd) - self.m_bytes_in_flight
        if not fast_resend and p.size - p.header_size > window_size_left and self.m_bytes_in_flight > 0:
            self.m_cwnd_full = True
            return False

        # plus one since we have fast-resend as well, which doesn't necessarily trigger by a timeout
        assert p.num_transmissions < self.socket_manager.num_resends() + 1

        assert p.size - p.header_size >= 0
        if p.need_resend:
            self.m_bytes_in_flight += p.size - p.header_size

        p.need_resend = False
        p.payload.timestamp_difference_microseconds = self.m_reply_micro
        p.send_time = datetime.datetime.now()
        timestamp_microseconds = int((p.send_time - datetime.datetime(1970, 1, 1)).total_seconds() * 1000000) & 0xFFFFFFFF
        p.payload.timestamp_microseconds = timestamp_microseconds

        # TODO no selective ack extension support yet

        p.payload.ack_nr = self.m_ack_nr

        packet = self.socket_manager.community.ezr_pack(UTPPayload.msg_id, p.payload)
        self.socket_manager.endpoint.send(self.m_remote_address, packet)
        self.m_out_packets += 1

    def maybe_inc_acked_seq_nr(self):
        incremented: bool = False

        # don't pass m_seq_nr, since we move into sequence numbers that haven't been sent yet, and aren't
        # supposed to be in m_outbuf
        # if the slot in m_outbuf is 0, it means the packet has been ACKed and removed from the send buffer
        while ((self.m_acked_seq_nr + 1) & ACK_MASK) != self.m_seq_nr and \
                self.m_outbuf.at((self.m_acked_seq_nr + 1) & ACK_MASK) is None:
            # increment the fast resend sequence number
            if self.m_fast_resend_seq_nr == self.m_acked_seq_nr:
                self.m_fast_resend_seq_nr = (self.m_fast_resend_seq_nr + 1) & ACK_MASK

            self.m_acked_seq_nr = (self.m_acked_seq_nr + 1) & ACK_MASK
            incremented = True

        if not incremented:
            return

        # update loss seq number if it's less than the packet that was just acked. If loss seq nr is greater,
        # it suggests that we're still in a window that has experienced loss
        if compare_less_wrap(self.m_loss_seq_nr, self.m_acked_seq_nr, ACK_MASK):
            self.m_loss_seq_nr = self.m_acked_seq_nr
        self.m_duplicate_acks = 0

    def ack_packet(self, p: UTPPayloadMetainfo, receive_time: datetime.datetime, seq_nr: int) -> int:
        assert p
        if not p.need_resend:
            assert self.m_bytes_in_flight >= p.size - p.header_size
            self.m_bytes_in_flight -= p.size - p.header_size

        if seq_nr == self.m_mtu_seq and self.m_mtu_seq != 0:
            assert p.mtu_probe
            # Our MTU probe was acked!
            self.m_mtu_floor = max(self.m_mtu_floor, p.size)
            self.update_mtu_limits()

        # Increment the acked sequence number counter
        self.maybe_inc_acked_seq_nr()

        rtt = int((receive_time - p.send_time).total_seconds() * 1000000)
        if receive_time < p.send_time:
            # this means our clock is not monotonic. Just assume the RTT was 100 ms
            rtt = 100000

        self.logger.debug("acked packet %d (%d bytes) (rtt:%d)", seq_nr, p.size - p.header_size, rtt / 1000)

        self.m_rtt.add_sample(rtt // 1000)
        return rtt

    def incoming_packet(self, payload: UTPPayload, peer: Peer, receive_time: datetime.datetime) -> bool:
        if payload.get_version() != 1:
            self.logger.warning("ERROR: incoming packet version:%d (ignored)", payload.get_version())
            return False

        if payload.get_type() != UTPPacketType.ST_SYN and payload.connection_id != self.m_recv_id:
            self.logger.warning("ERROR: incoming packet id:%d expected:%d (ignored)",
                                payload.connection_id, self.m_recv_id)
            return False

        if payload.get_type().value >= UTPPacketType.NUM_TYPES.value:
            self.logger.warning("ERROR: incoming packet type:%d (ignored)", payload.get_type())
            return False

        if self.m_state == UTPSocketState.NONE and payload.get_type() == UTPPacketType.ST_SYN:
            self.m_remote_address = peer.address

        if self.m_state != UTPSocketState.NONE and payload.get_type() == UTPPacketType.ST_SYN:
            self.logger.warning("ERROR: incoming packet type:ST_SYN (ignored)")
            return True

        step: bool = False
        if (receive_time - self.m_last_history_step).total_seconds() > 60:
            step = True
            self.m_last_history_step = receive_time

        # this is the difference between their send time and our receive time, 0 means no sample yet
        their_delay: int = 0
        if payload.timestamp_microseconds != 0:
            timestamp = int((receive_time - datetime.datetime(1970, 1, 1)).total_seconds() * 1000000) & 0xFFFFFFFF
            self.m_reply_micro = timestamp - payload.timestamp_microseconds
            prev_base: int = self.m_their_delay_hist.base() if self.m_their_delay_hist.initialized() else 0
            their_delay = self.m_their_delay_hist.add_sample(self.m_reply_micro, step)
            base_change: int = self.m_their_delay_hist.base() - prev_base
            self.logger.debug("their_delay::add_sample:%d prev_base:%d new_base:%d", self.m_reply_micro, prev_base, self.m_their_delay_hist.base())

            if prev_base and base_change < 0 and base_change > -10000 and self.m_delay_hist.initialized():
                # their base delay went down. This is caused by clock drift. To compensate, adjust our base delay
                # upwards. don't adjust more than 10 ms. If the change is that big, something is probably wrong.
                self.m_delay_hist.adjust_base(-base_change)

            self.logger.debug("incoming packet reply_micro:%d base_change:%d", self.m_reply_micro, base_change if prev_base else 0)

        # is this ACK valid? If the other end is ACKing a packet that hasn't been sent yet just ignore it.
        # A 3rd party could easily inject a packet like this in a stream, don't sever it because of it.
        # since m_seq_nr is the sequence number of the next packet we'll send (and m_seq_nr-1 was the last packet we
        # sent), if the ACK we got is greater than the last packet we sent something is wrong.
        # If our state is state_none, this packet must be a syn packet and the ack_nr should be ignored
        # Note that when we send a FIN, we don't increment m_seq_nr
        res: bool = ((self.m_state == UTPSocketState.SYN_SENT or self.m_state == UTPSocketState.FIN_SENT) and
                     payload.get_type() == UTPPacketType.ST_STATE)
        cmp_seq_nr: int = self.m_seq_nr if res else (self.m_seq_nr - 1) & ACK_MASK

        if (self.m_state != UTPSocketState.NONE or payload.get_type() != UTPPacketType.ST_SYN) and \
                (compare_less_wrap(cmp_seq_nr, payload.ack_nr, ACK_MASK) or
                 compare_less_wrap(payload.ack_nr, self.m_acked_seq_nr - dup_ack_limit, ACK_MASK)):
            self.logger.warning("ERROR: incoming packet ack_nr:%d our seq_nr:%d our acked_seq_nr:%d (ignored)",
                                payload.ack_nr, self.m_seq_nr, self.m_acked_seq_nr)
            return True

        # check to make sure the sequence number of this packet is reasonable. If it's a data packet and we've already
        # received it, ignore it. This is either a stray old packet that finally made it here (after having been
        # re-sent) or an attempt to interfere with the connection from a 3rd party
        # in both cases, we can safely ignore the timestamp and ACK information in this packet

        # if the socket is closing, always ignore any packet with a higher sequence number than the FIN sequence number
        # ST_STATE messages always include the next seqnr.
        if self.m_eof and (compare_less_wrap(self.m_eof_seq_nr, payload.seq_nr, ACK_MASK) or
                           (self.m_eof_seq_nr == payload.seq_nr and payload.get_type() != UTPPacketType.ST_STATE)):
            self.logger.warning("ERROR: incoming packet type: %s seq_nr:%d eof_seq_nr:%d (ignored)",
                                payload.get_type(), payload.seq_nr, self.m_eof_seq_nr)
            return True

        # the number of packets that'll fit in the reorder buffer
        max_packets_reorder: int = max(16, self.m_receive_buffer_capacity // 1100)

        if self.m_state != UTPSocketState.NONE and self.m_state != UTPSocketState.SYN_SENT and \
            compare_less_wrap((self.m_ack_nr + max_packets_reorder) & ACK_MASK, payload.seq_nr, ACK_MASK):
            self.logger.warning("ERROR: incoming packet seq_nr:%d our ack_nr:%d (ignored)",
                                payload.seq_nr, self.m_ack_nr)
            return True

        if payload.get_type() == UTPPacketType.ST_RESET:
            if compare_less_wrap(cmp_seq_nr, payload.ack_nr, ACK_MASK):
                self.logger.warning("ERROR: invalid RESET packet, ack_nr:%d our seq_nr:%d (ignored)",
                                    payload.ack_nr, self.m_seq_nr)
                return True

            self.logger.debug("incoming packet type:RESET")
            self.m_error = UTPError(UTPErrorCode.CONNECTION_RESET)
            self.m_state = UTPSocketState.ERROR_WAIT
            self.test_socket_state()
            return True

        self.m_in_packets += 1

        # this is a valid incoming packet, update the timeout timer
        self.m_num_timeouts = 0
        self.m_timeout = receive_time + datetime.timedelta(milliseconds=self.packet_timeout())
        self.logger.debug("updating timeout to: now + %d", self.packet_timeout())

        # the test for INT_MAX here is a work-around for a bug in uTorrent where it's sometimes sent as INT_MAX when
        # it is in fact uninitialized
        sample = 0 if payload.timestamp_difference_microseconds == 2**32-1 else payload.timestamp_difference_microseconds

        delay: int = 0
        if sample != 0:
            delay = self.m_delay_hist.add_sample(sample, step)
            self.m_delay_sample_hist[self.m_delay_sample_idx] = delay
            if self.m_delay_sample_idx >= len(self.m_delay_sample_hist):
                self.m_delay_sample_idx = 0

        acked_bytes: int = 0

        assert self.m_bytes_in_flight >= 0
        prev_bytes_in_flight: int = self.m_bytes_in_flight

        self.m_adv_wnd = payload.wnd_size

        # if we get an ack for the same sequence number as was last ACKed, and we have outstanding packets,
        # it counts as a duplicate ack. The reason to not count ST_DATA packets as duplicate ACKs is because we may
        # be receiving a stream of those regardless of our outgoing traffic, which makes their ACK number not
        # indicative of a dropped packet
        if payload.ack_nr == self.m_acked_seq_nr and self.m_outbuf.size() and payload.get_type() == UTPPacketType.ST_STATE:
            self.m_duplicate_acks += 1

        min_rtt: int = 2**32 - 1

        assert self.m_outbuf.at((self.m_acked_seq_nr + 1) & ACK_MASK) or ((self.m_seq_nr - self.m_acked_seq_nr) & ACK_MASK <= 1)

        # has this packet already been ACKed? if the ACK we just got is less than the max ACKed sequence number,
        # it doesn't tell us anything. So, only act on it if the ACK is greater than the last acked sequence number
        if self.m_state != UTPSocketState.NONE and compare_less_wrap(self.m_acked_seq_nr, payload.ack_nr, ACK_MASK):
            next_ack_nr: int = payload.ack_nr
            ack_nr: int = (self.m_acked_seq_nr + 1) & ACK_MASK
            while ack_nr != ((next_ack_nr + 1) & ACK_MASK):
                if self.m_fast_resend_seq_nr == ack_nr:
                    self.m_fast_resend_seq_nr = (self.m_fast_resend_seq_nr + 1) & ACK_MASK
                p = self.m_outbuf.remove(ack_nr)

                if not p:
                    continue

                acked_bytes += payload.size - payload.header_size
                rtt: int = self.ack_packet(p, receive_time, ack_nr)
                min_rtt = min(min_rtt, rtt)

                ack_nr = (ack_nr + 1) & ACK_MASK

            self.maybe_inc_acked_seq_nr()
            if self.m_outbuf.empty():
                self.m_duplicate_acks = 0

        # TODO interpret extension bytes

        # the send operation in parse_sack() may have set the socket to an error state, in which case we shouldn't
        # continue
        if self.m_state in [UTPSocketState.ERROR_WAIT, UTPSocketState.DELETING]:
            return True

        if self.m_duplicate_acks >= dup_ack_limit and ((self.m_acked_seq_nr + 1) & ACK_MASK) == self.m_fast_resend_seq_nr:
            # LOSS
            self.logger.debug("Packet %d lost. (%d duplicate acks, trigger fast-resend)",
                              self.m_fast_resend_seq_nr, self.m_duplicate_acks)

            # resend the lost packet
            p = self.m_outbuf.at(self.m_fast_resend_seq_nr)
            assert p

            # don't fast-resend this again
            self.m_fast_resend_seq_nr = (self.m_fast_resend_seq_nr + 1) & ACK_MASK

            if p:
                # don't consider a lost probe as proper loss, it doesn't necessarily signal congestion
                if not p.mtu_probe:
                    self.experienced_loss(self.m_fast_resend_seq_nr, receive_time)
                self.resend_packet(p, True)
                if self.m_state in [UTPSocketState.ERROR_WAIT, UTPSocketState.DELETING]:
                    return True

        payload_size: int = payload.get_payload_size()

        self.logger.debug("incoming packet seq_nr:%d ack_nr:%d type:%s id:%d size:%d timestampdiff:%u timestamp:%u "
                          "our ack_nr:%d our seq_nr:%d our acked_seq_nr:%d our state:%s",
                          payload.seq_nr, payload.ack_nr, payload.get_type(), payload.connection_id, payload_size,
                          payload.timestamp_difference_microseconds, payload.timestamp_microseconds, self.m_ack_nr,
                          self.m_seq_nr, self.m_acked_seq_nr, self.m_state)

        if payload.get_type() == UTPPacketType.ST_FIN:
            # We ignore duplicate FIN packets, but we still need to ACK them.
            if payload.seq_nr == ((self.m_ack_nr + 1) & ACK_MASK) or payload.seq_nr == self.m_ack_nr:
                self.logger.debug("FIN received in order")

                # The FIN arrived in order, nothing else is in the reorder buffer
                self.m_ack_nr = payload.seq_nr

                # Transition to state_t::fin_sent. The sent FIN is also an ack to the FIN we received.
                # Once we're in state_t::fin_sent we just need to wait for our FIN to be acked.
                if self.m_state == UTPSocketState.FIN_SENT:
                    self.send_pkt(pkt_ack)
                    if self.m_state in [UTPSocketState.ERROR_WAIT, UTPSocketState.DELETING]:
                        return True
                    else:
                        self.send_fin()
                        if self.m_state in [UTPSocketState.ERROR_WAIT, UTPSocketState.DELETING]:
                            return True

                        finish here

        return True
