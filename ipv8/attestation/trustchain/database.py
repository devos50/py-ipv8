"""
This file contains everything related to persistence for TrustChain.
"""
import json
import logging
import os
from binascii import hexlify

import rocksdb

from .payload import HalfBlockPayload
from .block import TrustChainBlock
from ...attestation.trustchain.blockcache import BlockCache
from ...database import database_blob
from ...messaging.serialization import default_serializer


class TrustChainDB(object):
    """
    Persistence layer for the TrustChain Community.
    Ensures a proper DB schema on startup.
    """
    LATEST_DB_VERSION = 7

    def __init__(self, working_directory, db_name, my_pk=None):
        """
        Sets up the persistence layer ready for use.
        :param working_directory: Path to the working directory
        that will contain the the db at working directory/DATABASE_PATH
        :param db_name: The name of the database
        :param my_pk: The public key of this user, used for caching purposes
        """
        db_path = os.path.join(working_directory, os.path.join(u"%s.db" % db_name))

        self.db = rocksdb.DB(db_path, rocksdb.Options(create_if_missing=True))
        if not self.db.get(b'blocks'):
            self.db.put(b'blocks', str(0).encode('utf-8'))

        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.debug("TrustChain database path: %s", db_path)
        self.db_name = db_name
        self.block_types = {}
        self.my_blocks_cache = None
        if my_pk:
            self.my_pk = my_pk
            self.my_blocks_cache = BlockCache(self, my_pk)

    def get_block_class(self, block_type):
        """
        Get the block class for a specific block type.
        """
        if block_type not in self.block_types:
            return TrustChainBlock

        return self.block_types[block_type]

    def add_block(self, block):
        """
        Persist a block
        :param block: The data that will be saved.
        """
        self.db.put(b'%s:%d' % (block.public_key, block.sequence_number), block.pack())
        self.db.put(block.hash, b'%s:%d' % (block.public_key, block.sequence_number))

        if block.link_sequence_number != 0:
            # Store the linked block
            self.db.put(b'%s:%d:l' % (block.public_key, block.sequence_number),
                        b'%s:%d' % (block.link_public_key, block.link_sequence_number))
            self.db.put(b'%s:%d:l' % (block.link_public_key, block.link_sequence_number),
                        b'%s:%d' % (block.public_key, block.sequence_number))

        # Update information about the latest block of this public key
        raw_pk_info = self.db.get(block.public_key)
        if not raw_pk_info:
            pk_info = {'latest_block_num': 0, 'types': {}, 'known_blocks': 0}
        else:
            pk_info = json.loads(raw_pk_info)

        pk_info['known_blocks'] += 1
        if block.sequence_number > pk_info['latest_block_num']:
            pk_info['latest_block_num'] = block.sequence_number

        self.db.put(block.public_key, json.dumps(pk_info).encode('utf-8'))

        # Update total number of blocks
        total_blocks = int(self.db.get(b'blocks'))
        total_blocks += 1
        self.db.put(b'blocks', str(total_blocks).encode('utf-8'))

        # TODO other maintainance

        if self.my_blocks_cache and (block.public_key == self.my_pk or block.link_public_key == self.my_pk):
            self.my_blocks_cache.add(block)

    def remove_block(self, block):
        """
        DANGER! USING THIS WILL LIKELY CAUSE A DOUBLE-SPEND IN THE NETWORK.
                ONLY USE IF YOU KNOW WHAT YOU ARE DOING.
        Remove a block from the database.

        :param block: The data that will be removed.
        """
        self.db.delete(b'%s:%d' % (block.public_key, block.sequence_number))

        # Update information about the latest block of this public key
        raw_pk_info = self.db.get(block.public_key)
        pk_info = json.loads(raw_pk_info)

        pk_info['known_blocks'] -= 1
        if block.sequence_number > pk_info['latest_block_num']:
            pk_info['latest_block_num'] = block.sequence_number

        self.db.put(block.public_key, json.dumps(pk_info).encode('utf-8'))

        # Update total number of blocks
        total_blocks = int(self.db.get(b'blocks'))
        total_blocks -= 1
        self.db.put(b'blocks', str(total_blocks).encode('utf-8'))

    def _getall(self, query, params):
        db_result = list(self.execute(self.get_sql_header() + query, params, fetch_all=True))
        return [self.get_block_class(db_item if isinstance(db_item, bytes)
                                     else str(db_item).encode('utf-8'))(db_item) for db_item in db_result]

    def get(self, public_key, sequence_number):
        """
        Get a specific block for a given public key
        :param public_key: The public_key for which the block has to be found.
        :param sequence_number: The specific block to get
        :return: the block or None if it is not known
        """
        raw_block = self.db.get(b'%s:%d' % (public_key, sequence_number))
        if not raw_block:
            return None

        payload = default_serializer.ez_unpack_serializables([HalfBlockPayload], raw_block)[0]
        block = self.get_block_class(payload.type).from_payload(payload, default_serializer)
        return block

    def get_all_blocks(self):
        """
        Return all blocks in the database.
        :return: all blocks in the database
        """
        return self._getall(u"", ())

    def get_number_of_known_blocks(self, public_key=None):
        """
        Return the total number of blocks in the database or the number of known blocks for a specific user.
        """
        if public_key:
            pk_info = self.db.get(public_key)
            if not pk_info:
                return 0

            pk_info = json.loads(pk_info)
            return int(pk_info['known_blocks'])

        return int(self.db.get(b'blocks'))

    def remove_old_blocks(self, num_blocks_to_remove, my_pub_key):
        """
        Remove old blocks from the database.
        :param num_blocks_to_remove: The number of blocks to remove from the database.
        :param my_pub_key: Your public key, specified since we don't want to remove your own blocks.
        """
        self.execute(u"DELETE FROM blocks WHERE block_hash IN "
                     u"(SELECT block_hash FROM blocks WHERE public_key != ? AND link_public_key != ?"
                     u" ORDER BY block_timestamp LIMIT ?)",
                     (database_blob(my_pub_key), database_blob(my_pub_key), num_blocks_to_remove))

    def get_block_with_hash(self, block_hash):
        """
        Return the block with a specific hash or None if it's not available in the database.
        :param block_hash: the hash of the block to search for.
        """
        block_key = self.db.get(block_hash)
        if not block_key:
            return None

        raw_block = self.db.get(block_key)
        if not block_key:
            return None

        payload = default_serializer.ez_unpack_serializables([HalfBlockPayload], raw_block)[0]
        block = self.get_block_class(payload.type).from_payload(payload, default_serializer)
        return block

    def get_blocks_with_type(self, block_type, public_key=None):
        """
        Return all blocks with a specific type.
        :param block_type: the type of the block we want to fetch.
        :param public_key: specify if we want only blocks of a specific peer.
        :return: All blocks with a specific type, optionally of a specific peer.
        """
        if public_key:
            return self._getall(u"WHERE type = ? and public_key = ?", (block_type, database_blob(public_key)))
        return self._getall(u"WHERE type = ?", (block_type,))

    def contains(self, block):
        """
        Check if a block is existent in the persistence layer.
        :param block: the block to check
        :return: True if the block exists, else false.
        """
        return self.get(block.public_key, block.sequence_number) is not None

    def get_latest(self, public_key, block_type=None):
        """
        Get the latest block for a given public key
        :param public_key: The public_key for which the latest block has to be found.
        :param block_type: A block type (optional). When specified, it returned the latest block of this type.
        :return: the latest block or None if it is not known
        """
        pk_info = self.db.get(public_key)
        if not pk_info:
            return None

        pk_info = json.loads(pk_info)

        if block_type:
            if block_type in pk_info['types']:
                return pk_info['types'][block_type]
            else:
                return None
        else:
            latest_block_num = pk_info['latest_block_num']

            raw_block = self.db.get(b'%s:%d' % (public_key, latest_block_num))
            if not raw_block:
                return None

            payload = default_serializer.ez_unpack_serializables([HalfBlockPayload], raw_block)[0]
            block = self.get_block_class(payload.type).from_payload(payload, default_serializer)
            return block

    def get_latest_blocks(self, public_key, limit=25, block_types=None):
        """
        Return the latest blocks for a given public key, optionally of a specific type
        :param public_key: The public_key for which the latest blocks have to be found.
        :param limit: The maximum number of blocks to return.
        :param block_types: A list of block types to return.
        :return: A list of blocks matching the given block types and public key.
        """
        latest_blocks = []
        latest_block = self.get_latest(public_key)
        if not latest_block:
            return []

        cur_seq_num = latest_block.sequence_number
        while cur_seq_num > 0 and len(latest_blocks) < limit:
            cur_block_raw = self.db.get(b'%s:%d' % (public_key, cur_seq_num))
            if not cur_block_raw:
                continue

            payload = default_serializer.ez_unpack_serializables([HalfBlockPayload], cur_block_raw)[0]
            cur_block = self.get_block_class(payload.type).from_payload(payload, default_serializer)

            if (block_types and cur_block.type in block_types) or not block_types:
                latest_blocks.append(cur_block)

            cur_seq_num -= 1

        return latest_blocks

    def get_block_after(self, block, block_type=None):
        """
        Returns database block with the lowest sequence number higher than the block's sequence_number
        :param block: The block who's successor we want to find
        :param block_type: A block type (optional). When specified, it only considers blocks of this type
        :return A block
        """

        # TODO consider block type!
        highest_block = self.get_latest(block.public_key, block_type)
        if not highest_block:
            return None

        if block.hash == highest_block.hash:
            return None
        cur_seq_num = block.sequence_number + 1
        while cur_seq_num <= highest_block.sequence_number:
            raw_block = self.db.get(b"%s:%d" % (block.public_key, cur_seq_num))
            if raw_block:
                payload = default_serializer.ez_unpack_serializables([HalfBlockPayload], raw_block)[0]
                block = self.get_block_class(payload.type).from_payload(payload, default_serializer)
                return block

            cur_seq_num += 1

        return None

    def get_block_before(self, block, block_type=None):
        """
        Returns database block with the highest sequence number lower than the block's sequence_number
        :param block: The block who's predecessor we want to find
        :return A block
        """

        # TODO consider block type!
        cur_seq_num = block.sequence_number - 1
        while cur_seq_num > 0:
            raw_block = self.db.get(b"%s:%d" % (block.public_key, cur_seq_num))
            if raw_block:
                payload = default_serializer.ez_unpack_serializables([HalfBlockPayload], raw_block)[0]
                block = self.get_block_class(payload.type).from_payload(payload, default_serializer)
                return block

            cur_seq_num -= 1

        return None

    def get_lowest_sequence_number_unknown(self, public_key):
        """
        Return the lowest sequence number that we don't have a block of in the chain of a specific peer.
        :param public_key: The public key
        """

        latest_block = self.get_latest(public_key)
        if not latest_block:
            return 1

        cur_seq_num = 1
        while cur_seq_num < latest_block.sequence_number:
            raw_block = self.get(public_key, cur_seq_num)
            if not raw_block:
                return cur_seq_num
            cur_seq_num += 1

        # Otherwise, we are missing the block immediately after the latest block
        return latest_block.sequence_number + 1

    def get_lowest_range_unknown(self, public_key):
        """
        Get the range of blocks (created by the peer with public_key) that we do not have yet.
        For instance, if a user has the following blocks in the database: [1, 4, 5, 9], then this method will return
        the tuple (2, 3).
        :param public_key: The public key of the peer we want to get missing blocks from.
        :return: A tuple indicating the start and end of the range of missing blocks.
        """
        lowest_unknown = self.get_lowest_sequence_number_unknown(public_key)
        latest_block = self.get_latest(public_key)
        if not latest_block:
            return 1, 1

        cur_seq_num = lowest_unknown + 1
        while cur_seq_num < latest_block.sequence_number:
            cur_block = self.get(public_key, cur_seq_num)
            if cur_block:
                return lowest_unknown, cur_seq_num - 1
            cur_seq_num += 1

        return lowest_unknown, latest_block.sequence_number - 1

    def get_linked(self, block):
        """
        Get the block that is linked to the given block
        :param block: The block for which to get the linked block
        :return: the latest block or None if it is not known
        """
        linked_key = self.db.get(b"%s:%d:l" % (block.public_key, block.sequence_number))
        if linked_key:
            linked_block_raw = self.db.get(linked_key)
            if not linked_block_raw:
                return None
            payload = default_serializer.ez_unpack_serializables([HalfBlockPayload], linked_block_raw)[0]
            block = self.get_block_class(payload.type).from_payload(payload, default_serializer)
            return block

    def get_all_linked(self, block):
        """
        Return all linked blocks for a specific block.
        :param block: The block for which to get the linked block
        :return: A list of all linked blocks
        """
        return self._getall(u"WHERE public_key = ? AND sequence_number = ? OR link_public_key = ? AND "
                            u"link_sequence_number = ?", (database_blob(block.link_public_key),
                                                          block.link_sequence_number, database_blob(block.public_key),
                                                          block.sequence_number))

    def crawl(self, public_key, start_seq_num, end_seq_num, limit=100):
        if self.my_blocks_cache and public_key == self.my_pk:
            # We are requesting blocks in our own chain, use the block cache.
            return self.my_blocks_cache.get_range(start_seq_num, end_seq_num)
        else:
            query = u"SELECT * FROM (%s WHERE sequence_number >= ? AND sequence_number <= ? AND public_key = ? " \
                    u"LIMIT ?) UNION SELECT * FROM (%s WHERE link_sequence_number >= ? AND link_sequence_number <= ? " \
                    u"AND link_sequence_number != 0 AND link_public_key = ? LIMIT ?)" % \
                    (self.get_sql_header(), self.get_sql_header())
            db_result = list(self.execute(query, (start_seq_num, end_seq_num, database_blob(public_key), limit,
                                                  start_seq_num, end_seq_num, database_blob(public_key), limit),
                                          fetch_all=True))
            return [self.get_block_class(db_item[0])(db_item) for db_item in db_result]

    def get_recent_blocks(self, limit=10, offset=0):
        """
        Return the most recent blocks in the TrustChain database.
        """
        return self._getall(u"ORDER BY block_timestamp DESC LIMIT ? OFFSET ?", (limit, offset))

    def get_users(self, limit=100):
        """
        Return information about the users in the database
        """
        res = list(self.execute(
            u"SELECT DISTINCT public_key, MAX(sequence_number) FROM blocks GROUP BY public_key "
            u"ORDER BY MAX(sequence_number) DESC LIMIT ? ", (limit,)))
        users_info = []
        for user_info in res:
            users_info.append({
                "public_key": hexlify(user_info[0] if isinstance(user_info[0], bytes) else str(user_info[0])),
                "blocks": user_info[1],
            })
        return users_info

    def get_connected_users(self, public_key, limit=100):
        """
        Return a list of connected users for a user with the given public key.
        :param public_key: Public key of the user
        :param limit: Limit on number of results to return
        :return: List of connected users (public key and latest block sequence number)
        """
        res = list(self.execute(
            u"SELECT DISTINCT b1.public_key as pk, MAX(b1.sequence_number) as max_seq FROM blocks b1 "
            u"WHERE b1.link_public_key=? GROUP BY pk "
            u"UNION "
            u"SELECT DISTINCT b2.link_public_key as pk, MAX(b2.sequence_number) as max_seq FROM blocks b2 "
            u"WHERE b2.public_key=? GROUP BY pk "
            u"ORDER BY max_seq DESC LIMIT ? ",
            (database_blob(public_key), database_blob(public_key), limit)))

        users_info = []
        for user_info in res:
            users_info.append({
                "public_key": hexlify(user_info[0] if isinstance(user_info[0], bytes) else str(user_info[0])),
                "blocks": user_info[1],
            })
        return users_info

    def add_double_spend(self, block1, block2):
        """
        Add information about a double spend to the database.
        """
        sql = u"INSERT OR IGNORE INTO double_spends (type, tx, public_key, sequence_number, link_public_key," \
              u"link_sequence_number,previous_hash, signature, block_timestamp, block_hash) VALUES(?,?,?,?,?,?,?,?,?,?)"
        self.execute(sql, block1.pack_db_insert())
        self.execute(sql, block2.pack_db_insert())
        self.commit()

    def did_double_spend(self, public_key):
        """
        Return whether a specific user did a double spend in the past.
        """
        count = list(self.execute(u"SELECT COUNT(*) FROM double_spends WHERE public_key = ?",
                                  (database_blob(public_key),)))[0][0]
        return count > 0

    def get_sql_header(self):
        """
        Return the first part of a generic sql select query.
        """
        _columns = u"type, tx, public_key, sequence_number, link_public_key, link_sequence_number, " \
                   u"previous_hash, signature, block_timestamp, insert_time"
        return u"SELECT " + _columns + u" FROM blocks "

    def close(self):
        del self.db
