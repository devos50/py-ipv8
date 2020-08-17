import logging
import random
import time
from binascii import hexlify
from collections import namedtuple
from hashlib import sha256

import orjson as json

from .payload import HalfBlockPayload
from ...database import database_blob
from ...keyvault.crypto import default_eccrypto
from ...messaging.serialization import PackError, default_serializer


HASH_LENGTH = 32
GENESIS_HASH = b'0' * HASH_LENGTH  # ID of the first block of the chain.
EMPTY_HASH = b'0' * HASH_LENGTH
GENESIS_SEQ = 1
UNKNOWN_SEQ = 0
EMPTY_SIG = b'0' * 64
EMPTY_PK = b'0' * 74
ANY_COUNTERPARTY_PK = EMPTY_PK
SKIP_ATTRIBUTES = {'key', 'serializer', 'crypto', '_transaction', '_logger'}


class TrustChainBlock(object):
    """
    Container for TrustChain block information
    """
    Data = namedtuple('Data', ['type',
                               'transaction',
                               'public_key',
                               'sequence_number',
                               'link_public_key',
                               'link_sequence_number',
                               'link_hash',
                               'previous_hash',
                               'previous_hash_set',
                               'signature',
                               'timestamp',
                               'insert_time'])
    """
    Data struct to initialize a TrustChainBlock.


        **[0] type:** The block type name, as utf-8 string or utf-8 encoded bytes.

        *> type:* str or bytes

        **[1] transaction:** Metadata dictionary, consisting of binary type strings.

        *> type:* dict

        **[2] public_key:** The serialized public key of the initiator of this block (binary data).

        *> type:* bytes (Py3) or str (Py2)

        **[3] sequence_number:** The the sequence number of this block in the chain of the intiator of this block.

        *> type:* int

        **[4] link_public_key:** The serialized public key of the counterparty of this block (binary data).

        *> type:* bytes (Py3) or str (Py2)

        **[5] link_sequence_number:** The height of this block in the chain of the counterparty of this block,
        or 0 if unknown.

        *> type:* int

        **[6] previous_hash:** The hash of the previous block in the chain of the initiator of this block (binary data).

        *> type:* bytes (Py3) or str (Py2)

        **[7] signature:** The signature of the initiator of this block for this block (binary data).

        *> type:* bytes (Py3) or str (Py2)

        **[8] timestamp:** The time in milliseconds since the UNIX epoch when this block was created
        (according to the initiator).

        *> type:* int

        **[9] insert_time:** The time in milliseconds since the UNIX epoch when this block was inserted into the local
        database (according to the local database), if this block was inserted into the local database.

        *> type:* int or None
    """

    def __init__(self, data=None, serializer=default_serializer):
        """
        Create a new TrustChainBlock or load a TrustChainBlock from an existing database entry.

        :param data: Optional data to initialize this block with.
        :type data: TrustChainBlock.Data or list
        :param serializer: An optional custom serializer to use for this block.
        :type serializer: Serializer
        """
        super(TrustChainBlock, self).__init__()
        self.serializer = serializer
        if data is None:
            # data
            self.type = b'unknown'
            self.transaction = {}
            self._transaction = json.dumps({})
            # identity
            self.public_key = EMPTY_PK
            self.sequence_number = GENESIS_SEQ
            # linked identity
            self.link_public_key = EMPTY_PK
            self.link_sequence_number = UNKNOWN_SEQ
            self.link_hash = EMPTY_HASH
            # validation
            self.previous_hash = GENESIS_HASH
            self.previous_hash_set = []
            self.signature = EMPTY_SIG
            self.timestamp = int(time.time() * 1000)
            # debug stuff
            self.insert_time = None
        else:
            self._transaction = data[1] if isinstance(data[1], bytes) else bytes(data[1])
            self.transaction = json.loads(self._transaction)
            (self.type, self.public_key, self.sequence_number, self.link_public_key, self.link_sequence_number, self.link_hash,
             self.previous_hash, raw_prev_hashes, self.signature, self.timestamp, self.insert_time) = (data[0], data[2], data[3],
                                                                                      data[4], data[5], data[6],
                                                                                      data[7], data[8], data[9],
                                                                                      data[10], data[11])
            self.type = self.type if isinstance(self.type, bytes) else str(self.type).encode('utf-8')
            self.public_key = self.public_key if isinstance(self.public_key, bytes) else bytes(self.public_key)
            self.link_public_key = (self.link_public_key if isinstance(self.link_public_key, bytes)
                                    else bytes(self.link_public_key))
            self.link_hash = (self.link_hash if isinstance(self.link_hash, bytes) else bytes(self.link_hash))
            self.previous_hash = (self.previous_hash if isinstance(self.previous_hash, bytes)
                                  else bytes(self.previous_hash))
            self.signature = self.signature if isinstance(self.signature, bytes) else bytes(self.signature)

            # Parse the previous hashes
            self.previous_hash_set = []
            prev_seq_nums = TrustChainBlock.get_prev_blocks(self.public_key, self.sequence_number, 10)
            num_previous_hashes = len(raw_prev_hashes) // HASH_LENGTH
            for hash_index in range(num_previous_hashes):
                raw_hash = raw_prev_hashes[hash_index * HASH_LENGTH:hash_index * HASH_LENGTH + HASH_LENGTH]
                self.previous_hash_set.append((prev_seq_nums[hash_index], raw_hash))

        self.hash = self.calculate_hash()
        self.crypto = default_eccrypto
        self._logger = logging.getLogger(self.__class__.__name__)

    @classmethod
    def get_prev_blocks(cls, public_key, sequence_number, num_pointers):
        # Determine the seed for the randomness
        random_seed = int(hexlify(sha256(public_key + b"%d" % sequence_number).digest()), 16)
        rand = random.Random(random_seed)
        seq_nums = []
        num_pointers = min(num_pointers, sequence_number - 1)
        for _ in range(num_pointers):
            rand_seq_num = rand.randint(1, sequence_number - 1)
            while rand_seq_num in seq_nums:
                rand_seq_num = rand.randint(1, sequence_number - 1)
            seq_nums.append(rand_seq_num)

        seq_nums.sort()
        return seq_nums

    @classmethod
    def from_payload(cls, payload, serializer):
        """
        Create a block according to a given payload and serializer.
        This method can be used when receiving a block from the network.
        """
        return cls([payload.type, payload.transaction, payload.public_key, payload.sequence_number,
                    payload.link_public_key, payload.link_sequence_number, payload.link_hash, payload.previous_hash,
                    payload.previous_hash_set, payload.signature, payload.timestamp, time.time()], serializer)

    @classmethod
    def from_pair_payload(cls, payload, serializer):
        """
        Create two half blocks from a block pair message, according to a given payload and serializer.
        Used to construct two blocks when receiving a block pair from the network.
        """
        block1 = cls([payload.type1, payload.transaction1, payload.public_key1, payload.sequence_number1,
                      payload.link_public_key1, payload.link_sequence_number1, payload.link_hash1, payload.previous_hash1,
                      payload.previous_hash_set1, payload.signature1, payload.timestamp1, time.time()], serializer)
        block2 = cls([payload.type2, payload.transaction2, payload.public_key2, payload.sequence_number2,
                      payload.link_public_key2, payload.link_sequence_number2, payload.link_hash2, payload.previous_hash2,
                      payload.previous_hash_set2, payload.signature2, payload.timestamp2, time.time()], serializer)
        return block1, block2

    def __str__(self):
        # This makes debugging and logging easier
        return "Block {0} from ...{1}:{2} links ...{3}:{4} h:{5} plinks:{6} for {7} type {8}".format(
            hexlify(self.hash)[-8:],
            hexlify(self.public_key)[-8:],
            self.sequence_number,
            hexlify(self.link_public_key)[-8:],
            self.link_sequence_number,
            self.link_hash,
            len(self.previous_hash_set),
            self.transaction,
            self.type)

    def __hash__(self):
        return int(hexlify(self.hash), 16)

    def __eq__(self, other):
        if not isinstance(other, TrustChainBlock):
            return False
        return self.pack() == other.pack()

    def calculate_hash(self):
        return sha256(self.pack()).digest()

    @property
    def block_id(self):
        return b"%s.%d" % (hexlify(self.public_key), self.sequence_number)

    @property
    def linked_block_id(self):
        return b"%s.%d" % (hexlify(self.link_public_key), self.link_sequence_number)

    @property
    def is_genesis(self):
        return self.sequence_number == GENESIS_SEQ and self.previous_hash == GENESIS_HASH

    @property
    def hash_number(self):
        """
        Return the hash of this block as a number (used as crawl ID).
        """
        return int(hexlify(self.hash), 16) % 100000000

    def serialized_previous_hash_set(self):
        serialized = b"".join([block_hash for _, block_hash in self.previous_hash_set])
        return serialized

    def pack(self, signature=True):
        """
        Encode this block for transport
        :param signature: False to pack EMPTY_SIG in the signature location, true to pack the signature field
        :return: the database_blob the data was packed into
        """
        previous_hashes = self.serialized_previous_hash_set()
        args = [self.public_key, self.sequence_number, self.link_public_key, self.link_sequence_number, self.link_hash,
                self.previous_hash, previous_hashes, self.signature if signature else EMPTY_SIG, self.type, self._transaction,
                self.timestamp]
        return self.serializer.pack_multiple(HalfBlockPayload(*args).to_pack_list())[0]

    def validate_transaction(self, database):
        """
        Validates the transaction of this block
        :param database: the database to check against
        :return: A tuple consisting of a ValidationResult and a list of user string errors
        """
        return ValidationResult.valid, []

    def validate(self, database):
        """
        Validates this block against what is known in the database
        :param database: the database to check against
        :return: A tuple consisting of a ValidationResult and a list of user string errors
        """

        # Start with a valid result.
        result = ValidationResult()

        # The validity of blocks is immutable. Once they are accepted they cannot change validation result. Blocks can
        # get inserted into the database in any order, so we need to find successors, predecessors as well as the block
        # itself and its linked block.
        blk = database.get(self.public_key, self.sequence_number)
        link = database.get_linked(self)
        prev_blk = database.get_block_before(self)
        next_blk = database.get_block_after(self)

        # Update the validation result through checking the block invariant.
        self.update_block_invariant(database, result)

        # Check if this block as retrieved from our database is the same as this block.
        self.update_block_consistency(blk, result, database)

        # Check if the linked block as retrieved from our database is the same as the one linked by this block.
        self.update_linked_consistency(database, link, result)

        # Check if the chain of blocks is properly hooked up.
        self.update_chain_consistency(database, prev_blk, next_blk, result)

        return result

    def update_block_invariant(self, database, result):
        """
        Validate that the block is sane, including the validity of the transaction.

        Some basic self tests. It is possible to violate these when constructing a block in code or getting a block
        from the database. The wire format is such that it impossible to hit many of these for blocks that went over
        the network.

        :param database: the database to use
        :type database: TrustChainDB
        :param result: the result to update
        :type result: ValidationResult
        :returns: None
        """
        tx_validate_res, tx_errors = self.validate_transaction(database)
        if tx_validate_res != ValidationResult.valid:
            result.state = tx_validate_res
            result.errors += tx_errors

        if self.sequence_number < GENESIS_SEQ:
            result.err("Sequence number is prior to genesis")
        if self.link_sequence_number < GENESIS_SEQ and self.link_sequence_number != UNKNOWN_SEQ:
            result.err("Link sequence number not empty and is prior to genesis")
        if self.timestamp < 0:
            result.err("Timestamp cannot be negative")
        if not self.crypto.is_valid_public_bin(self.public_key):
            result.err("Public key is not valid")
        else:
            # If the public key is valid, we can use it to check the signature. We want just a yes/no answer here, and
            # we want to keep checking for more errors, so just catch all packing exceptions and err() if any happen.
            try:
                pck = self.pack(signature=False)
            except PackError as e:
                self._logger.debug("Failed to pack 'self.pack' (error %s)", e)
                pck = None
            if pck is None or not self.crypto.is_valid_signature(
                    self.crypto.key_from_public_bin(self.public_key), pck, self.signature):
                result.err("Invalid signature")
        if not self.crypto.is_valid_public_bin(self.link_public_key) and \
                self.link_public_key != ANY_COUNTERPARTY_PK and \
                self.link_public_key != EMPTY_PK:
            result.err("Linked public key is not valid")
        if self.public_key == self.link_public_key:
            # Blocks to self serve no purpose and are thus invalid.
            result.err("Self signed block")
        if self.sequence_number == GENESIS_SEQ and self.previous_hash != GENESIS_HASH:
            result.err("Sequence number implies previous hash should be Genesis ID")
        if self.sequence_number != GENESIS_SEQ and self.previous_hash == GENESIS_HASH:
            result.err("Sequence number implies previous hash should not be Genesis ID")

    def update_block_consistency(self, blk, result, database):
        """
        Check if a given block is consistent with this block.

        If so it should be equal or else we caught a branch in someones trustchain.

        :param blk: the block to check for consistency with this block
        :type blk: TrustChainBlock or None
        :param result: the result to update
        :type result: ValidationResult
        :param database: the TrustChain database object, used to store detected double spend attempts
        :type database: TrustChainDB
        :returns: None
        """
        if blk:
            if blk.link_public_key != self.link_public_key:
                result.err("Link public key does not match known block")
            if blk.link_sequence_number != self.link_sequence_number:
                result.err("Link sequence number does not match known block")
            if blk.previous_hash != self.previous_hash:
                result.err("Previous hash does not match known block")
            if blk.signature != self.signature:
                result.err("Signature does not match known block")
            # if the known block is not equal, and the signatures are valid, we have a double signed PK/seq. Fraud!
            if self.hash != blk.hash and "Invalid signature" not in result.errors and\
               "Public key is not valid" not in result.errors:
                result.err("Double sign fraud")
                database.add_double_spend(blk, self)
                result.did_double_spend = True
                self.write_fraud_time(blk.public_key)

    def update_linked_consistency(self, database, link, result):
        """
        If the database has a linked block check if the values match up.

        If the values do not match up someone comitted fraud, but it is impossible to decide who. So we just invalidate
        the block that is the latter to get validated. We can also detect double counter sign fraud at this point.

        :param database: the database to use
        :type database: TrustChainDB
        :param link: the linked block
        :type link: TrustChainBlock or None
        :param result: the result to update
        :type result: ValidationResult
        :returns: None
        """
        if link:
            if link.public_key != self.link_public_key:
                result.err("Known link public key does not match this block")
            elif (link.link_sequence_number != self.sequence_number
                  and link.sequence_number != self.link_sequence_number):
                result.err("No link to linked block")
            elif self.public_key != link.link_public_key and link.link_public_key != ANY_COUNTERPARTY_PK:
                result.err("Public key mismatch on linked block")

            if self.link_sequence_number != UNKNOWN_SEQ:
                # This is a confirmation
                if self.link_hash != link.hash:
                    # The confirmation points to an unknown block. This might indicate fraud.
                    result.is_inconsistent = True
                    result.inconsistent_blocks.add(self)
                    result.inconsistent_blocks.add(link)

                # self counter signs another block (link). If link has a linked block that is not equal to self,
                # then self is fraudulent, since it tries to countersign a block that is already countersigned
                linklinked = database.get_linked(link)
                if linklinked is not None and linklinked.hash != self.hash and \
                        link.link_public_key != ANY_COUNTERPARTY_PK:
                    result.is_inconsistent = True
                    result.inconsistent_blocks.add(self)
                    result.inconsistent_blocks.add(link)
                    result.inconsistent_blocks.add(linklinked)

                    result.err("Double countersign fraud")
            else:
                # This is a proposal
                if link.link_hash != self.hash:
                    # The confirmation attached to this proposal points to an unknown block. This might indicate fraud.
                    result.is_inconsistent = True
                    result.inconsistent_blocks.add(self)
                    result.inconsistent_blocks.add(link)
        else:
            # We do not have a linked block, however, we are still able to perform a few checks
            if self.link_sequence_number != UNKNOWN_SEQ:
                linked_next = database.get(self.link_public_key, self.link_sequence_number + 1)
                if linked_next and linked_next.previous_hash != self.link_hash:
                    result.is_inconsistent = True
                    result.inconsistent_blocks.add(self)
                    result.inconsistent_blocks.add(linked_next)

        linked_prev = database.get_linked_sq_pk(self.public_key, self.sequence_number - 1)
        if linked_prev and linked_prev.link_hash != self.previous_hash:
            result.is_inconsistent = True
            result.inconsistent_blocks.add(self)
            result.inconsistent_blocks.add(linked_prev)

    def update_chain_consistency(self, database, prev_blk, next_blk, result):
        """
        Check for chain order consistency.

        The previous block should point to us and this block should point to the next block.

        :param prev_blk: the previous block in the chain
        :type prev_blk: TrustChainBlock or None
        :param next_blk: the next block in the chain
        :type next_blk: TrustChainBlock or None
        :param result: the result to update
        :type result: ValidationResult
        :returns: None
        """
        is_prev_gap = prev_blk.sequence_number != self.sequence_number - 1 if prev_blk else True
        is_next_gap = next_blk.sequence_number != self.sequence_number + 1 if next_blk else True

        if prev_blk:
            if prev_blk.public_key != self.public_key:
                result.err("Previous block public key mismatch")
            if prev_blk.sequence_number >= self.sequence_number:
                result.err("Previous block sequence number mismatch")
            if not is_prev_gap and prev_blk.hash != self.previous_hash:
                result.err("Previous hash is not equal to the hash id of the previous block")
                result.did_double_spend = True
                # Is this fraud? It is certainly an error, but fixing it would require a different signature on the same
                # sequence number which is fraud.
                self.write_fraud_time(self.public_key)

        if next_blk:
            if next_blk.public_key != self.public_key:
                result.err("Next block public key mismatch")
            if next_blk.sequence_number <= self.sequence_number:
                result.err("Next block sequence number mismatch")
            if not is_next_gap and next_blk.previous_hash != self.hash:
                result.err("Next hash is not equal to the hash id of the block")
                result.did_double_spend = True
                # Again, this might not be fraud, but fixing it can only result in fraud.
                self.write_fraud_time(self.public_key)

        if (self.public_key, self.sequence_number - 1) in database.hash_map:
            prev_hash = database.hash_map[(self.public_key, self.sequence_number - 1)]
            if prev_hash != self.previous_hash:
                result.err("The previous hash does not align")
                result.did_double_spend = True
                self.write_fraud_time(self.public_key)

        # Check the previous hashes
        for prev_seq_num, prev_hash in self.previous_hash_set:
            if (self.public_key, prev_seq_num) in database.hash_map:
                blk_hash = database.hash_map[(self.public_key, prev_seq_num)]
                if prev_hash != blk_hash:
                    result.err("One of the previous hashes (sq %d) does not align" % prev_seq_num)
                    result.did_double_spend = True
                    self.write_fraud_time(self.public_key)
            else:
                database.hash_map[(self.public_key, prev_seq_num)] = prev_hash

    def sign(self, key):
        """
        Signs this block with the given key
        :param key: the key to sign this block with
        """
        self.signature = self.crypto.create_signature(key, self.pack(signature=False))
        self.hash = self.calculate_hash()

    @classmethod
    def create(cls, block_type, transaction, database, public_key, link=None, additional_info=None, link_pk=None, double_spend=False):
        """
        Create an empty next block.
        :param block_type: the type of the block to be constructed
        :param transaction: the transaction to use in this block
        :param database: the database to use as information source
        :param public_key: the public key to use for this block
        :param link: optionally create the block as a linked block to this block
        :param additional_info: additional information, which has a higher priority than the
               transaction when link exists
        :param link_pk: the public key of the counterparty in this transaction
        :param double_spend: whether we double spend.
        :return: A newly created block
        """
        blk = database.get_latest(public_key)
        if double_spend:
            # Remove the latest block + linked block from the database
            linked = database.get_linked(blk)
            if linked:
                database.remove_block(linked)
            database.remove_block(blk)

            # Load the new block
            blk = database.get_latest(public_key)

        ret = cls()
        if link:
            ret.type = link.type if link.link_public_key != ANY_COUNTERPARTY_PK else block_type
            ret.transaction = link.transaction if additional_info is None else additional_info
            ret.link_public_key = link.public_key
            ret.link_sequence_number = link.sequence_number
            ret.link_hash = link.hash
        else:
            ret.type = block_type
            ret.transaction = transaction
            ret.link_public_key = link_pk or EMPTY_PK
            ret.link_sequence_number = UNKNOWN_SEQ

        if blk:
            ret.sequence_number = blk.sequence_number + 1
            ret.previous_hash = blk.hash

            # Set the right previous hashes
            prev_seq_nums = TrustChainBlock.get_prev_blocks(public_key, ret.sequence_number, 10)
            for prev_seq_num in prev_seq_nums:
                prev_blk = database.get(public_key, prev_seq_num)
                ret.previous_hash_set.append((prev_seq_num, prev_blk.hash))

        ret._transaction = json.dumps(ret.transaction)
        ret.public_key = public_key
        ret.signature = EMPTY_SIG
        ret.hash = ret.calculate_hash()
        return ret

    def pack_db_insert(self):
        """
        Prepare a tuple to use for inserting into the database
        :return: A database insertable tuple
        """
        return (self.type, database_blob(self._transaction), database_blob(self.public_key),
                self.sequence_number, database_blob(self.link_public_key), self.link_sequence_number, self.link_hash,
                database_blob(self.previous_hash), database_blob(self.serialized_previous_hash_set()), database_blob(self.signature), self.timestamp,
                database_blob(self.hash))

    def __iter__(self):
        """
        This override allows one to take the dict(<block>) of a block.
        :return: generator to iterate over all properties of this block
        """
        for key, value in self.__dict__.items():
            if key in SKIP_ATTRIBUTES:
                continue
            if key == 'transaction':
                yield key, json.loads(self._transaction)
            elif isinstance(value, bytes) and key != "insert_time" and key != "type":
                yield key, hexlify(value).decode('utf-8')
            else:
                yield key, value.decode('utf-8') if isinstance(value, bytes) else value

    def write_fraud_time(self, public_key):
        with open("detection_time.txt", "a") as out:
            hex_pk = hexlify(public_key).decode()
            out.write("%s,%d\n" % (hex_pk, int(round(time.time() * 1000))))


class ValidationResult(object):
    """
    Contains the various results that the validator can return.
    """

    @staticmethod
    def valid():
        """
        The block does not violate any rules
        """
        pass

    @staticmethod
    def invalid():
        """
        The block violates at least one validation rule
        """
        pass

    def __init__(self):
        """
        Create a new ValidationResult instance with valid state and no errors.
        """
        self.state = ValidationResult.valid
        self.is_inconsistent = False
        self.inconsistent_blocks = set()
        self.did_double_spend = False
        self.errors = []

    def err(self, reason):
        """
        Invalidate this result and give a reason for the invalidation.

        :param reason: the reason for invalidation
        :type reason: str
        :return: None
        """
        self.state = ValidationResult.invalid
        self.errors.append(reason)
