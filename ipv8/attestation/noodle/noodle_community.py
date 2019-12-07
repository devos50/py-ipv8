from __future__ import absolute_import

import orjson
import os
import random
import struct
from binascii import unhexlify, hexlify

import networkx as nx
from twisted.internet import reactor
from twisted.internet.defer import Deferred

from twisted.internet.task import LoopingCall

from .gossip_community import GossipCommunity
from .noodle_payload import PeerCrawlRequestPayload, PeerCrawlResponsePayload
from .settings import SecurityMode
from ..trustchain.block import EMPTY_PK, UNKNOWN_SEQ
from ..trustchain.caches import CrawlRequestCache, IntroCrawlTimeout, ChainCrawlCache
from ..trustchain.community import TrustChainCommunity, synchronized
from ..trustchain.payload import HalfBlockBroadcastPayload, HalfBlockPairBroadcastPayload, HalfBlockPayload, HalfBlockPairPayload
from ...keyvault.crypto import default_eccrypto
from ...peerdiscovery.network import Network
from ...peerdiscovery.discovery import RandomWalk
from ...lazy_community import lazy_wrapper, lazy_wrapper_unsigned, lazy_wrapper_unsigned_wd
from ...messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ...peer import Peer
from ...util import addCallback


class NoodleCommunity(TrustChainCommunity):
    """
    The Noodle community.
    """

    def __init__(self, *args, **kwargs):
        self.ipv8 = kwargs.pop('ipv8', None)
        super(NoodleCommunity, self).__init__(*args, **kwargs)

        self.known_graph = None
        self.periodic_sync_lc = {}
        self.mem_db_flush_lc = None
        self.pex = {}
        self.pex_map = {}
        self.bootstrap_master = None
        self.audit_requests = {}
        self.minters = set()

        self.decode_map.update({
            chr(8): self.received_peer_crawl_request,
            chr(9): self.received_peer_crawl_response,
            chr(10): self.received_audit_proofs,
            chr(11): self.received_audit_proofs_request,
            chr(12): self.received_audit_request
        })

    def init_mem_db_flush(self, flush_time):
        if not self.mem_db_flush_lc:
            self.mem_db_flush_lc = self.register_task("mem_db_flush", LoopingCall(self.mem_db_flush))
            self.mem_db_flush_lc.start(flush_time)

    def mem_db_flush(self):
        self.persistence.commit_block_times()

    def trustchain_sync(self, community_id):
        self.logger.info("Sync for the info peer  %s", community_id)
        blk = self.persistence.get_latest_peer_block(community_id)
        val = self.pex[community_id].get_peers()
        # val = self.ipv8.overlays[self.pex_map[peer_mid]].get_peers()
        if blk:
            self.send_block(blk, address_set=val)
        # Send also the last pairwise block to the peers
        if community_id in self.persistence.peer_map:
            blk = self.persistence.get_last_pairwise_block(self.persistence.peer_map[community_id],
                                                           self.my_peer.public_key.key_to_bin())
            if blk:
                self.send_block_pair(blk[0], blk[1], address_set=val)

    def send_block(self, block, address=None, address_set=None, ttl=1):
        """
        Send a block to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        if ttl < 1:
            return
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if address:
            self.logger.debug("Sending block to (%s:%d) (%s)", address[0], address[1], block)
            payload = HalfBlockPayload.from_half_block(block).to_pack_list()
            packet = self._ez_pack(self._prefix, 1, [dist, payload], False)
            self.endpoint.send(address, packet)
        else:
            payload = HalfBlockBroadcastPayload.from_half_block(block, ttl).to_pack_list()
            packet = self._ez_pack(self._prefix, 5, [dist, payload], False)

            if address_set:
                f = min(len(address_set), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block in a back-channel  to %s peers", f)
                peers = (p.address for p in random.sample(address_set, f))
            else:
                f = min(len(self.get_peers()), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block in a main-channel  to %s peers", f)
                peers = (p.address for p in random.sample(self.get_peers(), f))
            for p in peers:
                self.endpoint.send(p, packet)
                # self.register_anonymous_task("send_block",
                #                             reactor.callLater(random.random() * 0.2, self.endpoint.send, p, packet))

            self.relayed_broadcasts.append(block.block_id)

    def send_block_pair(self, block1, block2, address=None, address_set=None, ttl=1):
        """
        Send a half block pair to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if address:
            self.logger.info("Sending block pair to (%s:%d) (%s and %s)", address[0], address[1], block1, block2)
            payload = HalfBlockPairPayload.from_half_blocks(block1, block2).to_pack_list()
            packet = self._ez_pack(self._prefix, 4, [dist, payload], False)
            self.endpoint.send(address, packet)
        else:

            payload = HalfBlockPairBroadcastPayload.from_half_blocks(block1, block2, ttl).to_pack_list()
            packet = self._ez_pack(self._prefix, 6, [dist, payload], False)
            if address_set:
                f = min(len(address_set), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block pair in a back-channel  to %s peers", f)
                peers = (p.address for p in random.sample(address_set, f))
            else:
                f = min(len(self.get_peers()), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block pair in a main-channel  to %s peers", f)
                peers = (p.address for p in random.sample(self.get_peers(), f))

            for p in peers:
                self.endpoint.send(p, packet)
                # self.register_anonymous_task("send_block_pair",
                #                             reactor.callLater(random.random() * 0.2, self.endpoint.send, p, packet))
            self.relayed_broadcasts.append(block1.block_id)

    def prepare_spend_transaction(self, pub_key, spend_value, **kwargs):
        # check the balance first
        my_pk = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(my_pk)
        my_balance = self.persistence.get_balance(my_id)

        if my_balance < spend_value:
            return None
        else:
            peer = self.get_hop_to_peer(pub_key)
            if not peer:
                self.logger.error("Tried all edges. My peer is not connected!")
                return None
            peer_id = self.persistence.key_to_id(peer.public_key.key_to_bin())
            pw_total = self.persistence.get_total_pairwise_spends(my_id, peer_id)
            added = {"value": spend_value, "total_spend": pw_total + spend_value}
            added.update(**kwargs)
            return peer, added

    def prepare_mint_transaction(self):
        # TODO: replace with settings
        mint_val = 1000
        if os.getenv('INIT_MINT'):
            mint_val = float(os.getenv('INIT_MINT'))

        minter = self.persistence.key_to_id(EMPTY_PK)
        pk = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(pk)
        total = self.persistence.get_total_pairwise_spends(minter, my_id)
        transaction = {"value": mint_val, "mint_proof": True, "total_spend": total + mint_val}
        return transaction

    def get_hop_to_peer(self, peer_pub_key):
        """
        Get next hop to peer
        :param peer_pub_key: public key of the destination
        :return: the next hop for the peer
        """
        p = self.get_peer_by_pub_key(peer_pub_key)
        if p:
            # Directly connected
            return p
        # Check if peer is part of any known community
        for p in self.get_all_communities_peers():
            if peer_pub_key == p.public_key.key_to_bin():
                self.logger.info("Choosing peer from community")
                return p
        # Look in the known_graph the path to the peer
        if not self.known_graph:
            self.logger.error("World graph is not known")
        else:
            source = self.my_peer.public_key.key_to_bin()
            target = peer_pub_key
            p = None
            while not p and len(self.known_graph[source]) > 0:
                paths = list(nx.all_shortest_paths(self.known_graph, source=source, target=target))
                random_path = random.choice(paths)
                if len(random_path) < 2:
                    self.logger.error("Path to key %s is less than 2 %s", peer_pub_key, str(random_path))
                else:
                    # Choose random path
                    p = self.get_peer_by_pub_key(random_path[1])
                    if not p:
                        # p is not connected !
                        self.logger.error("Got a path, but not connected! %s. Removing the edge ", random_path[1])
                        self.known_graph.remove_edge(source, random_path[1])
            return p

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockBroadcastPayload)
    def received_half_block_broadcast(self, source_address, dist, payload):
        """
        We received a half block, part of a broadcast. Disseminate it further.
        """
        payload.ttl -= 1
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        peer = Peer(payload.public_key, source_address)
        self.validate_persist_block(block, peer)

        if block.block_id not in self.relayed_broadcasts and payload.ttl > 0:
            if self.noodle_settings.use_informed_broadcast:
                fanout = self.settings.broadcast_fanout - 1
                self.informed_send_block(block, ttl=payload.ttl, fanout=fanout)
            else:
                self.send_block(block, ttl=payload.ttl)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairBroadcastPayload)
    def received_half_block_pair_broadcast(self, source_address, dist, payload):
        """
        We received a half block pair, part of a broadcast. Disseminate it further.
        """
        payload.ttl -= 1
        block1, block2 = self.get_block_class(payload.type1).from_pair_payload(payload, self.serializer)
        self.validate_persist_block(block1)
        self.validate_persist_block(block2)

        if block1.block_id not in self.relayed_broadcasts and payload.ttl > 0:
            if self.noodle_settings.use_informed_broadcast:
                fanout = self.settings.broadcast_fanout - 1
                self.informed_send_block(block1, block2, ttl=payload.ttl, fanout=fanout)
            else:
                reactor.callLater(0.5 * random.random(), self.send_block_pair, block1, block2, ttl=payload.ttl)

    def informed_send_block(self, block1, block2=None, ttl=None, fanout=None):
        """
        Spread block among your verified peers.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
        if block2:
            if block1.link_sequence_number == UNKNOWN_SEQ:
                block = block1
            else:
                block = block2
        else:
            block = block1
        # Get information about the block counterparties
        if not ttl:
            ttl = self.noodle_settings.ttl
        know_neigh = self.network.known_network.get_neighbours(block.public_key)
        if not know_neigh:
            # No neighbours known, spread randomly
            if block2:
                self.send_block_pair(block1, block2, ttl=ttl)
            else:
                self.send_block(block1, ttl=ttl)
        else:
            next_peers = set()
            for neigh in know_neigh:
                paths = self.network.known_network.get_path_to_peer(self.my_peer.public_key.key_to_bin(), neigh,
                                                                    cutoff=ttl + 1)
                for p in paths:
                    next_peers.add(p[1])
            res_fanout = fanout if fanout else self.settings.broadcast_fanout
            if len(next_peers) < res_fanout:
                # There is not enough information to build paths - choose at random
                for peer in random.sample(self.get_peers(), min(len(self.get_peers()),
                                                                res_fanout)):
                    next_peers.add(peer.public_key.key_to_bin())
            if len(next_peers) > res_fanout:
                next_peers = random.sample(list(next_peers), res_fanout)

            if block2:
                payload = HalfBlockPairBroadcastPayload.from_half_blocks(block1, block2, ttl).to_pack_list()
                packet = self._ez_pack(self._prefix, 6, [dist, payload], False)
            else:
                payload = HalfBlockBroadcastPayload.from_half_block(block, ttl).to_pack_list()
                packet = self._ez_pack(self._prefix, 5, [dist, payload], False)

            for peer_key in next_peers:
                peer = self.network.get_verified_by_public_key_bin(peer_key)
                self.logger.debug("Sending block to %s", peer)
                p = peer.address
                self.register_anonymous_task("informed_send_block",
                                             reactor.callLater(random.random() * 0.1,
                                                               self.endpoint.send, p, packet))

            self.relayed_broadcasts.append(block.block_id)

    def defered_sync_start(self, mid):
        self.periodic_sync_lc[mid].start(self.noodle_settings.sync_time)

    def defered_sync_stop(self, mid):
        self.periodic_sync_lc[mid].stop()

    def all_sync_stop(self):
        if self.mem_db_flush_lc:
            self.mem_db_flush_lc.stop()
        for mid in self.pex:
            self.defered_sync_stop(mid)

    def build_security_community(self, community_mid):
        # Start sync task after the discovery
        task = self.trustchain_sync \
            if self.noodle_settings.security_mode == SecurityMode.VANILLA \
            else self.trustchain_active_sync

        self.periodic_sync_lc[community_mid] = self.register_task("sync_" + str(community_mid),
                                                                  LoopingCall(task, community_mid))
        self.register_anonymous_task("sync_start_" + str(community_mid),
                                     reactor.callLater(random.random(),
                                                       self.defered_sync_start, community_mid))

    def init_minter_community(self):
        if self.my_peer.mid not in self.pex:
            self.logger.info('Creating own minter community')
            self.pex[self.my_peer.mid] = self
            self.build_security_community(self.my_peer.mid)

    def validate_claims(self, last_block, peer):
        from_peer = self.persistence.key_to_id(last_block.public_key)
        crawl_id = self.persistence.id_to_int(from_peer)
        if not self.request_cache.has(u"crawl", crawl_id):
            # Need to get more information from the peer to verify the claim
            # except_pack = orjson.dumps(list(self.persistence.get_known_chains(from_peer)))
            #
            self.logger.info("Request the peer status and audit proofs %s:%s", crawl_id, last_block.sequence_number)
            except_pack = orjson.dumps(list())
            if self.settings.security_mode == SecurityMode.VANILLA:
                crawl_deferred = self.send_peer_crawl_request(crawl_id, peer,
                                                              last_block.sequence_number, except_pack)
            else:
                crawl_deferred = self.send_audit_proofs_request(peer, last_block.sequence_number, crawl_id)
            return crawl_deferred
        else:
            return self.request_cache.get(u'crawl', crawl_id).crawl_deferred

    def validate_audit_proofs(self, proofs, block, peer):
        self.logger.info("Received audit proofs for block %s", block)
        if self.settings.security_mode == SecurityMode.VANILLA:
            return True
        p1 = orjson.loads(proofs[0])
        p2 = orjson.loads(proofs[1])
        if 'spends' in p1:
            pack_stat = proofs[0]
            pack_audit = proofs[1]
            status = p1
            audits = p2
        elif 'spends' in p2:
            pack_stat = proofs[1]
            pack_audit = proofs[0]
            status = p2
            audits = p1
        else:
            self.logger.error("Audits proofs are illformed")
            return False

        for v in audits.items():
            if not self.verify_audit(pack_stat, v):
                self.logger.error("Audit did not validate %s %s", v,
                                  status)

        peer_id = self.persistence.key_to_id(block.public_key)
        # Put audit status into the local db
        res = self.persistence.dump_peer_status(peer_id, status)
        self.persistence.add_peer_proofs(peer_id, status['seq_num'], status, pack_audit)
        return res

    def finalize_audits(self, audit_seq, status, audits):
        self.logger.info("Audit with seq number %s finalized", audit_seq)
        full_audit = dict(audits)
        packet = orjson.dumps(full_audit)
        # Update database audit proofs
        my_id = self.persistence.key_to_id(self.my_peer.public_key.key_to_bin())
        self.persistence.add_peer_proofs(my_id, audit_seq, status, packet)
        # Get peers requested
        processed_ids = set()
        for seq, peers_val in list(self.audit_requests.items()):
            if seq <= audit_seq:
                for p, audit_id in peers_val:
                    if (p, audit_id) not in processed_ids:
                        self.send_audit_proofs(p, audit_id, packet)
                        self.send_audit_proofs(p, audit_id, status)
                        processed_ids.add((p, audit_id))
                del self.audit_requests[seq]

    def trustchain_active_sync(self, community_mid):
        # choose the peers
        self.logger.info("Active Sync asking in the community %s", community_mid)
        # Get the peer list for the community
        peer_list = self.pex[community_mid].get_peers()
        # Get own last block in the community
        peer_key = self.my_peer.public_key.key_to_bin()
        block = self.persistence.get_latest(peer_key)
        if not block:
            self.logger.info("Peer has no block for audit. Skipping audit for now.")
            return
        seq_num = block.sequence_number
        seed = peer_key + bytes(seq_num)
        selected_peers = self.choose_community_peers(peer_list, seed, min(self.noodle_settings.com_size, len(peer_list)))
        s1 = self.form_peer_status_response(peer_key)
        # Send an audit request for the block + seq num
        # Now we send status + seq_num
        crawl_id = self.persistence.id_to_int(self.persistence.key_to_id(peer_key))
        # crawl_id = int(str(crawl_id))
        # Check if there are active crawl requests for this sequence number
        if not self.request_cache.get(u'crawl', crawl_id):
            crawl_deferred = Deferred()
            self.request_cache.add(CrawlRequestCache(self, crawl_id, crawl_deferred,
                                                     total_blocks=len(selected_peers), status=s1))
            self.logger.info("Requesting an audit from %s peers", len(selected_peers))
            for peer in selected_peers:
                self.send_peer_audit_request(peer, crawl_id, s1)
            # when enough audits received, finalize
            return addCallback(crawl_deferred, lambda audits: self.finalize_audits(seq_num, s1, audits))

    def choose_community_peers(self, com_peers, current_seed, commitee_size):
        random.seed(current_seed)
        return random.sample(com_peers, commitee_size)

    @synchronized
    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, PeerCrawlRequestPayload)
    def received_audit_proofs_request(self, source_address, dist, payload: PeerCrawlRequestPayload, data):
        # get last collected audit proof
        my_id = self.persistence.key_to_id(self.my_peer.public_key.key_to_bin())
        pack = self.persistence.get_peer_proofs(my_id, int(payload.seq_num))
        if pack:
            seq_num, status, proofs = pack
            # There is an audit request peer can answer
            self.send_audit_proofs(source_address, payload.crawl_id, proofs)
            self.send_audit_proofs(source_address, payload.crawl_id, status)
        else:
            # There is no ready audit. Remember and answer later
            if payload.seq_num not in self.audit_requests:
                self.audit_requests[payload.seq_num] = []
            self.audit_requests[payload.seq_num].append((source_address, payload.crawl_id))

    def send_audit_proofs_request(self, peer, seq_num, audit_id):
        """
        Send an audit proof for the peer;
        Expect status and audit proofs for the status
        """
        self._logger.debug("Sending audit proof request to peer %s:%d (seq num: %d, id: %s)",
                           peer.address[0], peer.address[1], seq_num, audit_id)
        crawl_deferred = Deferred()
        self.request_cache.add(CrawlRequestCache(self, audit_id, crawl_deferred, total_blocks=2))

        global_time = self.claim_global_time()
        payload = PeerCrawlRequestPayload(seq_num, audit_id, orjson.dumps(list())).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 11, [dist, payload], False)
        self.endpoint.send(peer.address, packet)
        return crawl_deferred

    @synchronized
    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, PeerCrawlResponsePayload)
    def received_audit_proofs(self, source_address, dist, payload, data):
        cache = self.request_cache.get(u"crawl", payload.crawl_id)
        if cache:
            if 'status' in cache.added:
                # status is known => This is audit collection initiated by my peer
                audit = orjson.loads(payload.chain)
                status = cache.added['status']
                # TODO: if audit not valid/resend with bigger peer set
                for v in audit.items():
                    cache.received_block(v)
                    # if not self.verify_audit(status, v):
                    #    self.logger.error("Received not valid audit %s %s", audit,
                    #                      payload.crawl_id)
            else:
                # Status is unknown - request status from the collector
                cache.received_block(payload.chain)

    def verify_audit(self, status, audit):
        # This is a claim of a conditional transaction
        pub_key = default_eccrypto.key_from_public_bin(unhexlify(audit[0]))
        sign = unhexlify(audit[1])

        return default_eccrypto.is_valid_signature(pub_key, status, sign)

    def send_audit_proofs(self, address, audit_id, audit_proofs):
        """
        Send audit proofs
        """
        self.logger.info("Sending audit prof %s to %s", audit_id, address)
        global_time = self.claim_global_time()
        payload = PeerCrawlResponsePayload(audit_id, audit_proofs).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 10, [dist, payload], False)
        self.endpoint.send(address, packet)

    def perform_audit(self, source_address, audit_request):
        peer_id = self.persistence.int_to_id(audit_request.crawl_id)
        # Put audit status into the local db
        peer_status = orjson.loads(audit_request.chain)
        res = self.persistence.dump_peer_status(peer_id, peer_status)
        if res:
            # Create an audit proof for the this sequence
            sign = default_eccrypto.create_signature(self.my_peer.key, audit_request.chain)
            # create an audit proof
            audit = {}
            my_id = hexlify(self.my_peer.public_key.key_to_bin()).decode()
            audit[my_id] = hexlify(sign).decode()
            self.send_audit_proofs(source_address, audit_request.crawl_id, orjson.dumps(audit))
        else:
            # This is invalid audit request, refusing to sign
            self.logger.error("Received invalid audit request id %s", audit_request.crawl_id)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, PeerCrawlResponsePayload)
    def received_peer_crawl_response(self, peer, dist, payload: PeerCrawlResponsePayload):

        cache = self.request_cache.get(u"crawl", payload.crawl_id)
        peer_id = self.persistence.int_to_id(payload.crawl_id)
        prev_balance = self.persistence.get_balance(peer_id)
        self.logger.info("Dump chain for %s, balance before is %s", peer_id, prev_balance)
        res = self.persistence.dump_peer_status(peer_id, orjson.loads(payload.chain))
        after_balance = self.persistence.get_balance(peer_id)
        self.logger.info("Dump chain for %s, balance after is %s", peer_id, after_balance)
        if after_balance < 0:
            self.logger.error("Balance if still negative!  %s", orjson.loads(payload.chain))
        if cache:
            cache.received_empty_response()
        else:
            self.logger.error("Received peer crawl with unknown crawl id/Performing audit %s", payload.crawl_id)
            # Might be an active audit request -> verify the status/send chain tests
            self.perform_audit(peer.address, payload)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, PeerCrawlResponsePayload)
    def received_audit_request(self, peer, dist, payload: PeerCrawlResponsePayload):

        cache = self.request_cache.get(u"crawl", payload.crawl_id)
        peer_id = self.persistence.int_to_id(payload.crawl_id)
        prev_balance = self.persistence.get_balance(peer_id)
        self.logger.info("Dump chain for %s, balance before is %s", peer_id, prev_balance)
        res = self.persistence.dump_peer_status(peer_id, orjson.loads(payload.chain))
        after_balance = self.persistence.get_balance(peer_id)
        self.logger.info("Dump chain for %s, balance after is %s", peer_id, after_balance)
        if after_balance < 0:
            self.logger.error("Balance if still negative!  %s", orjson.loads(payload.chain))

        self.logger.info("Received audit request %s from %s:%d", payload.crawl_id, peer.address[0], peer.address[1])
        # Might be an active audit request -> verify the status/send chain tests
        self.perform_audit(peer.address, payload)

    def get_all_communities_peers(self):
        peers = set()
        for mid in self.pex:
            val = self.pex[mid].get_peers()
            if val:
                peers.update(val)
        return peers

    def send_peer_crawl_response(self, peer, crawl_id, chain):
        """
        Send chain to response for the peer crawl
        """
        self._logger.info("Sending peer crawl response to peer %s:%d", peer.address[0], peer.address[1])
        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PeerCrawlResponsePayload(crawl_id, chain).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 9, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    def send_peer_audit_request(self, peer, crawl_id, chain):
        """
        Send an audit request to a peer
        """
        self._logger.info("Sending audit request to peer %s:%d", peer.address[0], peer.address[1])
        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PeerCrawlResponsePayload(crawl_id, chain).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 12, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    def form_peer_status_response(self, public_key):
        return orjson.dumps(self.persistence.get_peer_status(public_key))

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, PeerCrawlRequestPayload)
    def received_peer_crawl_request(self, peer, dist, payload: PeerCrawlRequestPayload):
        # Need to convince peer with minimum number of blocks send
        # Get latest pairwise blocks/ including self claims
        my_key = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(my_key)
        peer_id = self.persistence.int_to_id(payload.crawl_id)
        if peer_id != my_id:
            self.logger.error("Peer requests not my peer status %s", peer_id)
        pack_except = set(orjson.loads(payload.pack_except))
        s1 = self.form_peer_status_response(my_key)
        self.logger.info("Received peer crawl from node %s for range, sending status len %s",
                         hexlify(peer.public_key.key_to_bin())[-8:], len(s1))
        self.send_peer_crawl_response(peer, payload.crawl_id, s1)

    def send_peer_crawl_request(self, crawl_id, peer, seq_num, pack_except):
        """
        Send a crawl request to a specific peer.
        """
        crawl_deferred = Deferred()
        self.request_cache.add(CrawlRequestCache(self, crawl_id, crawl_deferred))
        self.logger.info("Requesting balance proof for peer %s at seq num %d with id %d",
                         hexlify(peer.public_key.key_to_bin())[-8:], seq_num, crawl_id)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PeerCrawlRequestPayload(seq_num, crawl_id, pack_except).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 8, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)
        return crawl_deferred

    @synchronized
    def introduction_response_callback(self, peer, dist, payload):
        # TODO call super?
        chain_length = None
        if payload.extra_bytes:
            chain_length = struct.unpack('>l', payload.extra_bytes)[0]

        if peer.address in self.network.blacklist:  # Do not crawl addresses in our blacklist (trackers)
            return
        known_minters = set(nx.get_node_attributes(self.known_graph, 'minter').keys())
        if not self.ipv8:
            self.logger.warning('No IPv8 service object available, cannot start PEXCommunity')
        elif peer.public_key.key_to_bin() in known_minters and peer.mid not in self.pex:
            community = GossipCommunity(self.my_peer, self.ipv8.endpoint, Network(), mid=peer.mid, max_peers=-1)
            self.ipv8.overlays.append(community)
            # Discover and connect to everyone for 50 seconds
            self.pex[peer.mid] = community
            # index = len(self.ipv8.overlays)
            # self.pex_map[peer.mid] = index
            if self.bootstrap_master:
                self.logger.info('Proceed with a bootstrap master')
                for k in self.bootstrap_master:
                    community.walk_to(k)
            else:
                self.ipv8.strategies.append((RandomWalk(community), -1))
            self.build_security_community(peer.mid)

        # Check if we have pending crawl requests for this peer
        has_intro_crawl = self.request_cache.has(u"introcrawltimeout", IntroCrawlTimeout.get_number_for(peer))
        has_chain_crawl = self.request_cache.has(u"chaincrawl", ChainCrawlCache.get_number_for(peer))
        if has_intro_crawl or has_chain_crawl:
            self.logger.debug("Skipping crawl of peer %s, another crawl is pending", peer)
            return

        if self.settings.crawler:
            self.crawl_chain(peer, latest_block_num=chain_length)
        else:
            known_blocks = self.persistence.get_number_of_known_blocks(public_key=peer.public_key.key_to_bin())
            if known_blocks < 1000 or random.random() > 0.5:
                self.request_cache.add(IntroCrawlTimeout(self, peer))
                self.crawl_lowest_unknown(peer, latest_block_num=chain_length)

    def get_peer_by_pub_key(self, pub_key):
        return self.network.get_service_peer_by_public_key_bin(pub_key, self.master_peer.mid)

    def get_peer_by_mid(self, peer_mid):
        for peer in self.get_peers():
            if peer.mid == peer_mid:
                return peer
