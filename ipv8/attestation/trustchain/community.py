"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
import logging
import os
import random
import struct
from asyncio import Future, ensure_future, get_event_loop
from binascii import hexlify, unhexlify
from collections import deque
from threading import RLock

from .block import ANY_COUNTERPARTY_PK, EMPTY_PK, GENESIS_SEQ, TrustChainBlock, UNKNOWN_SEQ, ValidationResult
from .caches import ChainCrawlCache, CrawlRequestCache, HalfBlockSignCache, IntroCrawlTimeout
from .database import TrustChainDB
from .payload import *
from ...attestation.trustchain.settings import TrustChainSettings
from ...community import Community
from ...lazy_community import lazy_wrapper, lazy_wrapper_unsigned, lazy_wrapper_unsigned_wd
from ...messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ...peer import Peer
from ...requestcache import RandomNumberCache, RequestCache
from ...taskmanager import task
from ...util import fail, maybe_coroutine, succeed


class TrustChainCommunity(Community):
    """
    Community for reputation based on TrustChain tamper proof interaction history.
    """
    master_peer = Peer(unhexlify("4c69624e61434c504b3a5730f52156615ecbcedb36c442992ea8d3c26b418edd8bd00e01dce26028cd"
                                 "1ebe5f7dce59f4ed59f8fcee268fd7f1c6dc2fa2af8c22e3170e00cdecca487745"))

    UNIVERSAL_BLOCK_LISTENER = b'UNIVERSAL_BLOCK_LISTENER'
    DB_CLASS = TrustChainDB
    DB_NAME = 'trustchain'
    version = b'\x02'

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        self.persistence = kwargs.pop('persistence', None)
        self.env = kwargs.pop('env', None)
        db_name = kwargs.pop('db_name', self.DB_NAME)
        self.settings = kwargs.pop('settings', TrustChainSettings())
        self.data_dir = kwargs.pop('data_dir')
        self.sim_settings = kwargs.pop('sim_settings')
        self.receive_block_lock = RLock()

        super(TrustChainCommunity, self).__init__(*args, **kwargs)
        self.request_cache = RequestCache()

        logs_dir = os.path.join(self.data_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        log_file = os.path.join(logs_dir, "%s.log" % hexlify(self.my_peer.public_key.key_to_bin()).decode()[-8:])
        self.logger = logging.getLogger(self.__class__.__name__) #setup_logger(self.__class__.__name__, log_file)

        if not self.persistence:
            self.persistence = self.DB_CLASS(working_directory, db_name, self.my_peer.public_key.key_to_bin())
        self.relayed_broadcasts = set()
        self.relayed_broadcasts_order = deque()
        self.logger.debug("The trustchain community started with Public Key: %s",
                          hexlify(self.my_peer.public_key.key_to_bin()))
        self.shutting_down = False
        self.listeners_map = {}  # Map of block_type -> [callbacks]
        self.register_task("db_cleanup", self.do_db_cleanup, interval=600)

        self.did_double_spend = False
        self.all_peers = None

        self.add_message_handler(HalfBlockPayload, self.received_half_block)
        self.add_message_handler(CrawlRequestPayload, self.received_crawl_request)
        self.add_message_handler(CrawlResponsePayload, self.received_crawl_response)
        self.add_message_handler(HalfBlockPairPayload, self.received_half_block_pair)
        self.add_message_handler(HalfBlockBroadcastPayload, self.received_half_block_broadcast)
        self.add_message_handler(HalfBlockPairBroadcastPayload, self.received_half_block_pair_broadcast)
        self.add_message_handler(EmptyCrawlResponsePayload, self.received_empty_crawl_response)
        self.add_message_handler(InconsistencyPairPayload, self.received_two_inconsistent_blocks)
        self.add_message_handler(InconsistencyTripletPayload, self.received_three_inconsistent_blocks)

    def start_crawling(self):
        if not self.env:
            return

        yield self.env.timeout(random.random() * self.sim_settings.crawl_interval * 1000)

        self.all_peers = self.get_peers()

        while True:
            peer = random.choice(self.all_peers)
            self.send_crawl_request(peer, peer.public_key.key_to_bin(), -1, -1)

            yield self.env.timeout(self.sim_settings.crawl_interval * 1000)

    def received_latest_blocks(self, peer, blocks, from_range, to_range):
        if not blocks or not (from_range == -1 and to_range == -1):
            return

        for block in blocks:
            if block.public_key == peer.public_key.key_to_bin():
                # Select random numbers
                if block and block.sequence_number > 1:
                    start_seq = random.randint(1, block.sequence_number - 1)
                else:
                    start_seq = 1

                crawl_batch_size = self.settings.crawl_batch_size
                end_seq = start_seq + crawl_batch_size
                self.send_crawl_request(peer, peer.public_key.key_to_bin(), start_seq, end_seq)
                self.logger.info("Crawling peer %s (%d - %d)", peer, start_seq, end_seq)

    def create_random_interactions(self):
        if not self.env:
            return

        self.all_peers = self.get_peers()

        yield self.env.timeout(random.random() * 1000)

        while True:
            double_spend = False
            latest_block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
            if random.random() <= self.sim_settings.double_spend_probability and not self.did_double_spend and latest_block and latest_block.sequence_number > 1:
                self.did_double_spend = True
                import chainsim.globals as global_vars
                global_vars.peers_committed_fraud += 1
                double_spend = True

                with open(os.path.join(self.data_dir, "fraud_time.txt"), "a") as out:
                    hex_pk = hexlify(self.my_peer.public_key.key_to_bin()).decode()
                    out.write("%s,%d\n" % (hex_pk, self.env.now))

            peer = random.choice(self.all_peers)
            # Make sure that we double spend with another peer
            while latest_block and (peer.public_key.key_to_bin() == latest_block.public_key or peer.public_key.key_to_bin() == latest_block.link_public_key):
                peer = random.choice(self.all_peers)

            self.sign_block(peer, peer.public_key.key_to_bin(), block_type=b'test', transaction={}, double_spend=double_spend)

            yield self.env.timeout(1000)

    def do_db_cleanup(self):
        """
        Cleanup the database if necessary.
        """
        blocks_in_db = self.persistence.get_number_of_known_blocks()
        if blocks_in_db > self.settings.max_db_blocks:
            my_pk = self.my_peer.public_key.key_to_bin()
            self.persistence.remove_old_blocks(blocks_in_db - self.settings.max_db_blocks, my_pk)

    def add_listener(self, listener, block_types):
        """
        Add a listener for specific block types.
        """
        for block_type in block_types:
            if block_type not in self.listeners_map:
                self.listeners_map[block_type] = []
            self.listeners_map[block_type].append(listener)
            self.persistence.block_types[block_type] = listener.BLOCK_CLASS

    def remove_listener(self, listener, block_types):
        for block_type in block_types:
            if block_type in self.listeners_map and listener in self.listeners_map[block_type]:
                self.listeners_map[block_type].remove(listener)
            if block_type in self.persistence.block_types:
                self.persistence.block_types.pop(block_type, None)

    def get_block_class(self, block_type):
        """
        Get the block class for a specific block type.
        """
        if block_type not in self.listeners_map or not self.listeners_map[block_type]:
            return TrustChainBlock

        return self.listeners_map[block_type][0].BLOCK_CLASS

    async def should_sign(self, block):
        """
        Return whether we should sign the block in the passed message.
        @param block: the block we want to sign or not.
        """
        if block.type not in self.listeners_map:
            return False  # There are no listeners for this block

        for listener in self.listeners_map[block.type]:
            should_sign = await maybe_coroutine(listener.should_sign, block)
            if should_sign:
                return True

        return False

    def _add_broadcasted_blockid(self, block_id):
        self.relayed_broadcasts.add(block_id)
        self.relayed_broadcasts_order.append(block_id)
        if len(self.relayed_broadcasts) > self.settings.broadcast_history_size:
            to_remove = self.relayed_broadcasts_order.popleft()
            self.relayed_broadcasts.remove(to_remove)

    def send_block(self, block, address=None, ttl=1):
        """
        Send a block to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        block_payload = HalfBlockPayload.from_half_block(block)

        if address:
            self.logger.debug("Sending block to (%s:%d) (%s)", address[0], address[1], block)
            self.endpoint.pass_payload(self.my_peer, address, 1, block_payload)
        else:
            self.logger.debug("Broadcasting block %s", block)
            broadcast_payload = HalfBlockBroadcastPayload(block_payload, ttl)
            for peer in random.sample(self.all_peers, min(len(self.all_peers), self.settings.broadcast_fanout)):
                self.endpoint.pass_payload(self.my_peer, peer.address, 5, broadcast_payload)
            self._add_broadcasted_blockid(block.block_id)

    def send_block_pair(self, block1, block2, address=None, ttl=1):
        """
        Send a half block pair to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if address:
            self.logger.debug("Sending block pair to (%s:%d) (%s and %s)", address[0], address[1], block1, block2)
            payload = HalfBlockPairPayload.from_half_blocks(block1, block2)
            self.endpoint.pass_payload(self.my_peer, address, 4, payload)
        else:
            self.logger.debug("Broadcasting blocks %s and %s", block1, block2)
            payload = HalfBlockPairBroadcastPayload.from_half_blocks(block1, block2, ttl)
            for peer in random.sample(self.all_peers, min(len(self.all_peers), self.settings.broadcast_fanout)):
                self.endpoint.pass_payload(self.my_peer, peer.address, 6, payload)
            self._add_broadcasted_blockid(block1.block_id)

    def self_sign_block(self, block_type=b'unknown', transaction=None):
        return self.sign_block(self.my_peer, block_type=block_type, transaction=transaction)

    def create_source_block(self, block_type=b'unknown', transaction=None):
        """
        Create a source block without any initial counterparty to sign.

        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :return: A future that fires with a (block, None) tuple
        """
        return self.sign_block(peer=None, public_key=ANY_COUNTERPARTY_PK,
                               block_type=block_type, transaction=transaction)

    def create_link(self, source, block_type, additional_info=None, public_key=None):
        """
        Create a Link Block to a source block

        :param source: The source block which had no initial counterpary to sign
        :param block_type: The type of the block to be constructed, as a string
        :param additional_info: a dictionary with supplementary information concerning the transaction
        :param public_key: The public key of the counterparty (usually of the source's owner)
        :return: None
        """
        public_key = source.public_key if public_key is None else public_key

        return self.sign_block(self.my_peer, linked=source, public_key=public_key, block_type=block_type,
                               additional_info=additional_info)

    def sign_block(self, peer, public_key=EMPTY_PK, block_type=b'unknown', transaction=None, linked=None,
                   additional_info=None, double_spend=False):
        """
        Create, sign, persist and send a block signed message
        :param peer: The peer with whom you have interacted, as a IPv8 peer
        :param public_key: The public key of the other party you transact with
        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :param linked: The block that the requester is asking us to sign
        :param additional_info: Stores additional information, on the transaction
        """
        # NOTE to the future: This method reads from the database, increments and then writes back. If in some future
        # this method is allowed to execute in parallel, be sure to lock from before .create up to after .add_block

        # In this particular case there must be an implicit transaction due to the following assert
        assert peer is not None or peer is None and linked is None and public_key == ANY_COUNTERPARTY_PK, \
            "Peer, linked block should not be provided when creating a no counterparty source block. Public key " \
            "should be that reserved for any counterpary."
        assert transaction is None and linked is not None or transaction is not None and linked is None, \
            "Either provide a linked block or a transaction, not both %s, %s" % (peer, self.my_peer)
        assert (additional_info is None or additional_info is not None and linked is not None
                and transaction is None and peer == self.my_peer and public_key == linked.public_key), \
            "Either no additional info is provided or one provides it for a linked block"
        assert (linked is None or linked.link_public_key == self.my_peer.public_key.key_to_bin()
                or linked.link_public_key == ANY_COUNTERPARTY_PK), "Cannot counter sign block not addressed to self"
        assert linked is None or linked.link_sequence_number == UNKNOWN_SEQ, \
            "Cannot counter sign block that is not a request"
        assert transaction is None or isinstance(transaction, dict), "Transaction should be a dictionary"
        assert additional_info is None or isinstance(additional_info, dict), "Additional info should be a dictionary"

        #self.persistence_integrity_check()

        if linked and linked.link_public_key != ANY_COUNTERPARTY_PK:
            block_type = linked.type

        block = self.get_block_class(block_type).create(block_type, transaction, self.persistence,
                                                        self.my_peer.public_key.key_to_bin(),
                                                        link=linked, additional_info=additional_info,
                                                        link_pk=public_key, double_spend=double_spend,
                                                        back_pointers=self.sim_settings.back_pointers)
        block.sign(self.my_peer.key)

        # validation = block.validate(self.persistence)
        # self.logger.info("Signed block to %s (%s) validation result %s",
        #                  hexlify(block.link_public_key)[-8:], block, validation)
        # if validation.state != ValidationResult.valid:
        #     self.logger.error("Signed block did not validate?! Result %s", validation.errors)
        #     return fail(RuntimeError("Signed block did not validate."))

        if not self.persistence.contains(block):
            self.persistence.add_block(block)
            self.notify_listeners(block)

        # This is a source block with no counterparty
        if not peer and public_key == ANY_COUNTERPARTY_PK:
            if block.type not in self.settings.block_types_bc_disabled and not double_spend:
                self.send_block(block)
            return succeed((block, None))

        # If there is a counterparty to sign, we send it
        self.send_block(block, address=peer.address)

        # We broadcast the block in the network if we initiated a transaction
        if block.type not in self.settings.block_types_bc_disabled and not linked and not double_spend:
            self.send_block(block)

        if peer == self.my_peer:
            # We created a self-signed block
            if block.type not in self.settings.block_types_bc_disabled and not double_spend:
                self.send_block(block)

            return succeed((block, None)) if public_key == ANY_COUNTERPARTY_PK else succeed((block, linked))
        elif not linked:
            # We keep track of this outstanding sign request.
            sign_future = Future()
            try:
                self.request_cache.add(HalfBlockSignCache(self, block, sign_future, peer.address))
            except RuntimeError:
                pass  # We ignore this one deliberately
            return sign_future
        else:
            # We return a future that fires immediately with both half blocks.
            if block.type not in self.settings.block_types_bc_disabled and not double_spend:
                self.send_block_pair(linked, block)

            return succeed((linked, block))

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPayload)
    def received_half_block(self, source_address, dist, payload):
        """
        We've received a half block, either because we sent a SIGNED message to some one or we are crawling
        """
        peer = Peer(payload.public_key, source_address)
        self.process_half_block_payload(peer, payload)

    def process_half_block_payload(self, peer, payload):
        block = self.persistence.blocks[payload.hash]

        try:
            self.process_half_block(block, peer)
        except RuntimeError as e:
            self.logger.info("Failed to process half block (error %s)", e)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockBroadcastPayload)
    def received_half_block_broadcast(self, source_address, dist, payload):
        """
        We received a half block, part of a broadcast. Disseminate it further.
        """
        self.process_half_block_broadcast_payload(payload)

    def process_half_block_broadcast_payload(self, payload):
        block = self.persistence.blocks[payload.block.hash]
        self.validate_persist_block(block)

        if block.block_id not in self.relayed_broadcasts and payload.ttl > 1:
            self.send_block(block, ttl=payload.ttl - 1)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairPayload)
    def received_half_block_pair(self, source_address, dist, payload):
        """
        We received a block pair message.
        """
        self.process_half_block_pair_payload(payload)

    def process_half_block_pair_payload(self, payload):
        block1 = self.persistence.blocks[payload.hash1]
        block2 = self.persistence.blocks[payload.hash2]

        self.validate_persist_block(block1)
        self.validate_persist_block(block2)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairBroadcastPayload)
    def received_half_block_pair_broadcast(self, source_address, dist, payload):
        """
        We received a half block pair, part of a broadcast. Disseminate it further.
        """
        self.process_half_block_pair_broadcast_payload(payload)

    def process_half_block_pair_broadcast_payload(self, payload):
        block1 = self.persistence.blocks[payload.hash1]
        block2 = self.persistence.blocks[payload.hash2]

        self.validate_persist_block(block1)
        self.validate_persist_block(block2)

        if block1.block_id not in self.relayed_broadcasts and payload.ttl > 1:
            self.send_block_pair(block1, block2, ttl=payload.ttl - 1)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, InconsistencyPairPayload)
    def received_two_inconsistent_blocks(self, source_address, dist, payload):
        block1 = self.get_block_class(payload.block1.type).from_payload(payload.block1, self.serializer,
                                                                        self.sim_settings.back_pointers)
        self.validate_persist_block(block1, should_share=False)
        block2 = self.get_block_class(payload.block2.type).from_payload(payload.block2, self.serializer,
                                                                        self.sim_settings.back_pointers)
        self.validate_persist_block(block2, should_share=False)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, InconsistencyTripletPayload)
    def received_three_inconsistent_blocks(self, source_address, dist, payload):
        block1 = self.get_block_class(payload.block1.type).from_payload(payload.block1, self.serializer,
                                                                        self.sim_settings.back_pointers)
        self.validate_persist_block(block1, should_share=False)
        block2 = self.get_block_class(payload.block2.type).from_payload(payload.block2, self.serializer,
                                                                        self.sim_settings.back_pointers)
        self.validate_persist_block(block2, should_share=False)
        block3 = self.get_block_class(payload.block3.type).from_payload(payload.block3, self.serializer,
                                                                        self.sim_settings.back_pointers)
        self.validate_persist_block(block3, should_share=False)

    def validate_persist_block(self, block, should_share=True):
        """
        Validate a block and if it's valid, persist it. Return the validation result.
        :param block: The block to validate and persist.
        :return: [ValidationResult]
        """
        validation = block.validate(self.persistence, self.data_dir)

        if validation.is_inconsistent and self.settings.share_inconsistencies and should_share and validation.state == ValidationResult.valid:
            self.broadcast_inconsistencies(validation.inconsistent_blocks)

        if validation.state == ValidationResult.invalid:
            pass
        elif not self.persistence.contains(block):
            self.persistence.add_block(block)
            self.notify_listeners(block)

        return validation

    def broadcast_inconsistencies(self, blocks):
        blocks = list(blocks)
        block1_payload = HalfBlockPayload.from_half_block(blocks[0])
        block2_payload = HalfBlockPayload.from_half_block(blocks[1])

        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if len(blocks) == 2:
            broadcast_payload = InconsistencyPairPayload(block1_payload, block2_payload).to_pack_list()
            packet = self._ez_pack(self._prefix, 8, [dist, broadcast_payload], False)
        elif len(blocks) == 3:
            block3_payload = HalfBlockPayload.from_half_block(blocks[2])
            broadcast_payload = InconsistencyTripletPayload(block1_payload, block2_payload, block3_payload).to_pack_list()
            packet = self._ez_pack(self._prefix, 9, [dist, broadcast_payload], False)

        peers = self.get_peers()
        self.logger.info("Sending %d inconsistent blocks to %d peers!", len(blocks), self.settings.inconsistency_fanout)
        for peer in random.sample(peers, min(len(peers), self.settings.broadcast_fanout)):
            self.endpoint.send(peer.address, packet)

    def notify_listeners(self, block):
        """
        Notify listeners of a specific new block.
        """
        # Call the listeners associated to the universal block, if there are any
        for listener in self.listeners_map.get(self.UNIVERSAL_BLOCK_LISTENER, []):
            listener.received_block(block)

        # Avoid proceeding any further if the type of the block coincides with the UNIVERSAL_BLOCK_LISTENER
        if block.type not in self.listeners_map or self.shutting_down or block.type == self.UNIVERSAL_BLOCK_LISTENER:
            return

        for listener in self.listeners_map[block.type]:
            listener.received_block(block)

    def process_half_block(self, blk, peer):
        """
        Process a received half block.
        """
        validation = self.validate_persist_block(blk)
        self.logger.info("Block validation result %s, %s, (%s)", validation.state, validation.errors, blk)
        if validation.state == ValidationResult.invalid:
            raise RuntimeError(f"Block could not be validated: {validation.state}, {validation.errors}")

        # Check if we are waiting for this signature response
        link_block_id_int = int(hexlify(blk.linked_block_id), 16) % 100000000
        if self.request_cache.has('sign', link_block_id_int):
            cache = self.request_cache.pop('sign', link_block_id_int)

            # We cannot guarantee that we're on the event loop thread.
            get_event_loop().call_soon_threadsafe(cache.sign_future.set_result,
                                                  (blk, self.persistence.get_linked(blk)))

        # Is this a request, addressed to us, and have we not signed it already?
        if (blk.link_sequence_number != UNKNOWN_SEQ
                or blk.link_public_key != self.my_peer.public_key.key_to_bin()
                or self.persistence.get_linked(blk) is not None):
            return

        self.logger.info("Received request block addressed to us (%s)", blk)

        try:
            should_sign = True
        except Exception as e:
            self.logger.error("Error while determining whether to sign (error: %s)", e)
            return

        if not should_sign:
            self.logger.info("Not signing block %s", blk)
            return

        self.sign_block(peer, linked=blk)

    def crawl_chain(self, peer, latest_block_num=0):
        """
        Crawl the whole chain of a specific peer.
        :param latest_block_num: The latest block number of the peer in question, if available.
        """
        if self.request_cache.has("chaincrawl", ChainCrawlCache.get_number_for(peer)):
            self.logger.debug("Skipping crawl of peer %s, another crawl is pending", peer)
            return succeed(None)

        crawl_future = Future()
        cache = ChainCrawlCache(self, peer, crawl_future, known_chain_length=latest_block_num)
        self.request_cache.add(cache)
        get_event_loop().call_soon_threadsafe(ensure_future, self.send_next_partial_chain_crawl_request(cache))
        return crawl_future

    def crawl_lowest_unknown(self, peer, latest_block_num=None):
        """
        Crawl the lowest unknown block of a specific peer.
        :param latest_block_num: The latest block number of the peer in question, if available
        """
        sq = self.persistence.get_lowest_sequence_number_unknown(peer.public_key.key_to_bin())
        if latest_block_num and sq == latest_block_num + 1:
            return []  # We don't have to crawl this node since we have its whole chain
        return self.send_crawl_request(peer, peer.public_key.key_to_bin(), sq, sq)

    def send_crawl_request(self, peer, public_key, start_seq_num, end_seq_num, for_half_block=None):
        """
        Send a crawl request to a specific peer.
        """
        crawl_id = for_half_block.hash_number if for_half_block else \
            RandomNumberCache.find_unclaimed_identifier(self.request_cache, "crawl")
        self.request_cache.add(CrawlRequestCache(self, crawl_id, peer, start_seq_num, end_seq_num))
        self.logger.info("Requesting crawl of node %s (blocks %d to %d) with id %d",
                         hexlify(peer.public_key.key_to_bin())[-8:], start_seq_num, end_seq_num, crawl_id)

        payload = CrawlRequestPayload(public_key, start_seq_num, end_seq_num, crawl_id)
        self.endpoint.pass_payload(self.my_peer, peer.address, 2, payload)

    @task
    async def perform_partial_chain_crawl(self, cache, start, stop):
        """
        Perform a partial crawl request for a specific range, when crawling a chain.
        :param cache: The cache that stores progress regarding the chain crawl.
        :param start: The sequence number of the first block to be requested.
        :param stop: The sequence number of the last block to be requested.
        """
        if cache.current_request_range != (start, stop):
            # We are performing a new request
            cache.current_request_range = start, stop
            cache.current_request_attempts = 0
        elif cache.current_request_attempts == 3:
            # We already tried the same request three times, bail out
            self.request_cache.pop("chaincrawl", cache.number)
            cache.crawl_future.set_result(None)
            return

        cache.current_request_attempts += 1
        await self.send_crawl_request(cache.peer, cache.peer.public_key.key_to_bin(), start, stop)
        await self.send_next_partial_chain_crawl_request(cache)

    async def send_next_partial_chain_crawl_request(self, cache):
        """
        Send the next partial crawl request, if we are not done yet.
        :param cache: The cache that stores progress regarding the chain crawl.
        """
        lowest_unknown = self.persistence.get_lowest_sequence_number_unknown(cache.peer.public_key.key_to_bin())
        if cache.known_chain_length and cache.known_chain_length == lowest_unknown - 1:
            # At this point, we have all the blocks we need
            self.request_cache.pop("chaincrawl", cache.number)
            cache.crawl_future.set_result(None)
            return

        if not cache.known_chain_length:
            # Do we know the chain length of the crawled peer? If not, make sure we get to know this first.
            blocks = await self.send_crawl_request(cache.peer, cache.peer.public_key.key_to_bin(), -1, -1)
            if not blocks:
                self.request_cache.pop("chaincrawl", cache.number)
                cache.crawl_future.set_result(None)
                return

            cache.known_chain_length = blocks[0].sequence_number
            await self.send_next_partial_chain_crawl_request(cache)
            return

        latest_block = self.persistence.get_latest(cache.peer.public_key.key_to_bin())
        if not latest_block:
            # We have no knowledge of this peer but we have the length of the chain.
            # Simply send a request from the genesis block to the known chain length.
            self.perform_partial_chain_crawl(cache, 1, cache.known_chain_length)
            return
        elif latest_block and lowest_unknown == latest_block.sequence_number + 1:
            # It seems that we filled all gaps in the database; check whether we can do one final request
            if latest_block.sequence_number < cache.known_chain_length:
                self.perform_partial_chain_crawl(cache, latest_block.sequence_number + 1, cache.known_chain_length)
            else:
                self.request_cache.pop("chaincrawl", cache.number)
                cache.crawl_future.set_result(None)
            return

        start, stop = self.persistence.get_lowest_range_unknown(cache.peer.public_key.key_to_bin())
        self.perform_partial_chain_crawl(cache, start, stop)

    @lazy_wrapper(GlobalTimeDistributionPayload, CrawlRequestPayload)
    def received_crawl_request(self, peer, dist, payload):
        self.logger.info("Received crawl request from node %s for range %d-%d",
                         hexlify(peer.public_key.key_to_bin())[-8:], payload.start_seq_num, payload.end_seq_num)
        self.process_crawl_request(peer, payload)

    def process_crawl_request(self, peer, payload):
        start_seq_num = payload.start_seq_num
        end_seq_num = payload.end_seq_num

        # It could be that our start_seq_num and end_seq_num are negative. If so, convert them to positive numbers,
        # based on the last block of ones chain.
        if start_seq_num < 0:
            last_block = self.persistence.get_latest(payload.public_key)
            start_seq_num = max(GENESIS_SEQ, last_block.sequence_number + start_seq_num + 1) \
                if last_block else GENESIS_SEQ
        if end_seq_num < 0:
            last_block = self.persistence.get_latest(payload.public_key)
            end_seq_num = max(GENESIS_SEQ, last_block.sequence_number + end_seq_num + 1) \
                if last_block else GENESIS_SEQ

        blocks = self.persistence.crawl(payload.public_key, start_seq_num, end_seq_num,
                                        limit=self.settings.max_crawl_batch)
        if self.settings.crawl_send_random_blocks > 0:
            random_blocks = self.persistence.get_random_blocks(self.settings.crawl_send_random_blocks)
            if random_blocks:
                blocks.extend(random_blocks)

        total_count = len(blocks)

        if total_count == 0:
            global_time = self.claim_global_time()
            response_payload = EmptyCrawlResponsePayload(payload.crawl_id).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
            packet = self._ez_pack(self._prefix, 7, [dist, response_payload], False)
            self.endpoint.send(peer.address, packet)
        else:
            self.send_crawl_responses(blocks, peer, payload.crawl_id)

    def send_crawl_responses(self, blocks, peer, crawl_id):
        """
        Answer a peer with crawl responses.
        """
        for ind, block in enumerate(blocks):
            self.send_crawl_response(block, crawl_id, ind + 1, len(blocks), peer)
        self.logger.info("Sent %d blocks", len(blocks))

    def sanitize_database(self):
        """
        DANGER! USING THIS MAY CAUSE DOUBLE SPENDING IN THE NETWORK.
                ONLY USE IF YOU KNOW WHAT YOU ARE DOING.

        This method removes all of the invalid blocks in our own chain.
        """
        self.logger.error("Attempting to recover %s", self.DB_CLASS.__name__)
        block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        if not block:
            # There is nothing to corrupt, we're at the genesis block.
            self.logger.debug("No latest block found when trying to recover database!")
            return
        validation = self.validate_persist_block(block)
        while validation.state != ValidationResult.valid:
            # The latest block is invalid, remove it.
            self.persistence.remove_block(block)
            self.logger.error("Removed invalid block %d from our chain", block.sequence_number)
            block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
            if not block:
                # Back to the genesis
                break
            validation = self.validate_persist_block(block)
        self.logger.error("Recovered database, our last block is now %d", block.sequence_number if block else 0)

    def persistence_integrity_check(self):
        """
        Perform an integrity check of our own chain. Recover it if needed.
        """
        block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        if not block:
            return
        validation = self.validate_persist_block(block)
        if validation.state != ValidationResult.valid:
            self.logger.error("Our chain did not validate. Result %s", repr(validation))
            self.sanitize_database()

    def send_crawl_response(self, block, crawl_id, index, total_count, peer):
        self.logger.debug("Sending block for crawl request to %s (%s)", peer, block)

        block_payload = HalfBlockPayload.from_half_block(block)
        payload = CrawlResponsePayload(block_payload, crawl_id, index, total_count)

        self.endpoint.pass_payload(self.my_peer, peer.address, 3, payload)

    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, CrawlResponsePayload)
    def received_crawl_response(self, source_address, dist, payload, data):
        peer = Peer(payload.block.public_key, source_address)
        self.process_crawl_response_payload(peer, payload)

    def process_crawl_response_payload(self, peer, payload):
        block = self.persistence.blocks[payload.block.hash]

        try:
            self.process_half_block(block, peer)
        except RuntimeError as e:
            self.logger.info("Failed to process half block (error %s)", e)

        cache = self.request_cache.get("crawl", payload.crawl_id)
        if cache:
            cache.received_block(block, payload.total_count)

    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, EmptyCrawlResponsePayload)
    def received_empty_crawl_response(self, source_address, dist, payload, data):
        cache = self.request_cache.get("crawl", payload.crawl_id)
        if cache:
            self.logger.info("Received empty crawl response for crawl with ID %d", payload.crawl_id)
            cache.received_empty_response()

    def get_chain_length(self):
        """
        Return the length of your own chain.
        """
        latest_block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        return 0 if not latest_block else latest_block.sequence_number

    def create_introduction_request(self, socket_address, extra_bytes=b''):
        extra_bytes = struct.pack('>l', self.get_chain_length())
        return super(TrustChainCommunity, self).create_introduction_request(socket_address, extra_bytes)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b''):
        extra_bytes = struct.pack('>l', self.get_chain_length())
        return super(TrustChainCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                             identifier, introduction, extra_bytes)

    def introduction_response_callback(self, peer, dist, payload):
        chain_length = None
        if payload.extra_bytes:
            chain_length = struct.unpack('>l', payload.extra_bytes)[0]

        if peer.address in self.network.blacklist:  # Do not crawl addresses in our blacklist (trackers)
            return

        # Check if we have pending crawl requests for this peer
        has_intro_crawl = self.request_cache.has("introcrawltimeout", IntroCrawlTimeout.get_number_for(peer))
        has_chain_crawl = self.request_cache.has("chaincrawl", ChainCrawlCache.get_number_for(peer))
        if has_intro_crawl or has_chain_crawl:
            self.logger.debug("Skipping crawl of peer %s, another crawl is pending", peer)
            return

        if self.settings.crawler:
            self.crawl_chain(peer, latest_block_num=chain_length)
        # else:
        #     known_blocks = self.persistence.get_number_of_known_blocks(public_key=peer.public_key.key_to_bin())
        #     if known_blocks < 1000 or random.random() > 0.5:
        #         self.request_cache.add(IntroCrawlTimeout(self, peer))
        #         self.crawl_lowest_unknown(peer, latest_block_num=chain_length)

    async def unload(self):
        self.logger.debug("Unloading the TrustChain Community.")
        self.shutting_down = True

        await self.request_cache.shutdown()

        await super(TrustChainCommunity, self).unload()

        # Close the persistence layer
        self.persistence.close()


class TrustChainTestnetCommunity(TrustChainCommunity):
    """
    This community defines the testnet for TrustChain
    """
    DB_NAME = 'trustchain_testnet'

    master_peer = Peer(unhexlify("4c69624e61434c504b3aa90c1e65d68e9f0ccac1385b58e4a605add2406aff9952b1b6435ab07e5385"
                                 "5eb07b062ca33af9ec55b45446dbbefc3752523a4fd3b659ecd1d8e172b7b7f30d"))
