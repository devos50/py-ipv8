from ...messaging.lazy_payload import vp_compile, VariablePayload
from ...messaging.payload import Payload


@vp_compile
class CrawlRequestPayload(VariablePayload):
    """
    Request a crawl of blocks starting with a specific sequence number or the first if 0.
    """

    msg_id = 2
    format_list = ['74s', 'l', 'l', 'I']
    names = ['public_key', 'start_seq_num', 'end_seq_num', 'crawl_id']


@vp_compile
class EmptyCrawlResponsePayload(VariablePayload):
    """
    Payload for the message that indicates that there are no blocks to respond.
    """

    msg_id = 7
    format_list = ['I']
    names = ['crawl_id']


@vp_compile
class HalfBlockPayload(VariablePayload):
    """
    Payload for message that ships a half block
    """

    msg_id = 1
    format_list = ['74s', 'I', '74s', 'I', '32s', '32s', '64s', 'varlenI', 'varlenI', 'Q']
    names = ['public_key', 'sequence_number', 'link_public_key', 'link_sequence_number', 'link_hash', 'previous_hash',
             'signature', 'type', 'transaction', 'timestamp']

    @classmethod
    def from_half_block(cls, block):
        return HalfBlockPayload(
            block.public_key,
            block.sequence_number,
            block.link_public_key,
            block.link_sequence_number,
            block.link_hash,
            block.previous_hash,
            block.signature,
            block.type,
            block._transaction,
            block.timestamp
        )


@vp_compile
class InconsistencyPairPayload(VariablePayload):
    msg_id = 8
    format_list = [HalfBlockPayload, HalfBlockPayload]
    names = ['block1', 'block2']


@vp_compile
class InconsistencyTripletPayload(VariablePayload):
    msg_id = 9
    format_list = [HalfBlockPayload, HalfBlockPayload, HalfBlockPayload]
    names = ['block1', 'block2', 'block3']


@vp_compile
class HalfBlockBroadcastPayload(VariablePayload):
    """
    Payload for a message that contains a half block and a TTL field for broadcasts.
    """

    msg_id = 5
    format_list = [HalfBlockPayload, 'I']
    names = ['block', 'ttl']


@vp_compile
class CrawlResponsePayload(VariablePayload):
    """
    Payload for the response to a crawl request.
    """

    msg_id = 3
    format_list = [HalfBlockPayload, 'I', 'I', 'I']
    names = ['block', 'crawl_id', 'cur_count', 'total_count']


class HalfBlockPairPayload(Payload):
    """
    Payload for message that ships two half blocks
    """

    msg_id = 4
    format_list = ['74s', 'I', '74s', 'I', '32s', '32s', '64s', 'varlenI', 'varlenI', 'Q'] * 2

    def __init__(self, public_key1, sequence_number1, link_public_key1, link_sequence_number1, link_hash1, previous_hash1,
                 signature1, block_type1, transaction1, timestamp1, public_key2, sequence_number2, link_public_key2,
                 link_sequence_number2, link_hash2, previous_hash2, signature2, block_type2, transaction2, timestamp2):
        super(HalfBlockPairPayload, self).__init__()
        self.public_key1 = public_key1
        self.sequence_number1 = sequence_number1
        self.link_public_key1 = link_public_key1
        self.link_sequence_number1 = link_sequence_number1
        self.link_hash1 = link_hash1
        self.previous_hash1 = previous_hash1
        self.signature1 = signature1
        self.type1 = block_type1
        self.transaction1 = transaction1
        self.timestamp1 = timestamp1

        self.public_key2 = public_key2
        self.sequence_number2 = sequence_number2
        self.link_public_key2 = link_public_key2
        self.link_sequence_number2 = link_sequence_number2
        self.link_hash2 = link_hash2
        self.previous_hash2 = previous_hash2
        self.signature2 = signature2
        self.type2 = block_type2
        self.transaction2 = transaction2
        self.timestamp2 = timestamp2

    @classmethod
    def from_half_blocks(cls, block1, block2):
        return HalfBlockPairPayload(
            block1.public_key,
            block1.sequence_number,
            block1.link_public_key,
            block1.link_sequence_number,
            block1.link_hash,
            block1.previous_hash,
            block1.signature,
            block1.type,
            block1._transaction,
            block1.timestamp,
            block2.public_key,
            block2.sequence_number,
            block2.link_public_key,
            block2.link_sequence_number,
            block2.link_hash,
            block2.previous_hash,
            block2.signature,
            block2.type,
            block2._transaction,
            block2.timestamp
        )

    def to_pack_list(self):
        data = [('74s', self.public_key1),
                ('I', self.sequence_number1),
                ('74s', self.link_public_key1),
                ('I', self.link_sequence_number1),
                ('32s', self.link_hash1),
                ('32s', self.previous_hash1),
                ('64s', self.signature1),
                ('varlenI', self.type1),
                ('varlenI', self.transaction1),
                ('Q', self.timestamp1),
                ('74s', self.public_key2),
                ('I', self.sequence_number2),
                ('74s', self.link_public_key2),
                ('I', self.link_sequence_number2),
                ('32s', self.link_hash2),
                ('32s', self.previous_hash2),
                ('64s', self.signature2),
                ('varlenI', self.type2),
                ('varlenI', self.transaction2),
                ('Q', self.timestamp2)]

        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockPairPayload(*args)


class HalfBlockPairBroadcastPayload(HalfBlockPairPayload):
    """
    Payload for a broadcast message that ships two half blocks
    """

    msg_id = 6
    format_list = ['74s', 'I', '74s', 'I', '32s', '32s', '64s', 'varlenI', 'varlenI', 'Q'] * 2 + ['I']

    def __init__(self, public_key1, sequence_number1, link_public_key1, link_sequence_number1, link_hash1, previous_hash1,
                 signature1, block_type1, transaction1, timestamp1, public_key2, sequence_number2, link_public_key2,
                 link_sequence_number2, link_hash2, previous_hash2, signature2, block_type2, transaction2, timestamp2, ttl):
        super(HalfBlockPairBroadcastPayload, self).__init__(public_key1, sequence_number1, link_public_key1,
                                                            link_sequence_number1, link_hash1, previous_hash1, signature1,
                                                            block_type1, transaction1, timestamp1, public_key2,
                                                            sequence_number2, link_public_key2, link_sequence_number2, link_hash2,
                                                            previous_hash2, signature2, block_type2, transaction2,
                                                            timestamp2)
        self.ttl = ttl

    @classmethod
    def from_half_blocks(cls, block1, block2, ttl):
        return HalfBlockPairBroadcastPayload(
            block1.public_key,
            block1.sequence_number,
            block1.link_public_key,
            block1.link_sequence_number,
            block1.link_hash,
            block1.previous_hash,
            block1.signature,
            block1.type,
            block1._transaction,
            block1.timestamp,
            block2.public_key,
            block2.sequence_number,
            block2.link_public_key,
            block2.link_sequence_number,
            block2.link_hash,
            block2.previous_hash,
            block2.signature,
            block2.type,
            block2._transaction,
            block2.timestamp,
            ttl
        )

    def to_pack_list(self):
        data = super(HalfBlockPairBroadcastPayload, self).to_pack_list()
        data.append(('I', self.ttl))
        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockPairBroadcastPayload(*args)


class DHTBlockPayload(Payload):
    """
    Class which represents the payloads published to the DHT for disseminating chunks of TrustChain blocks
    """
    format_list = ['64s', 'H', 'H', 'H', 'raw']
    PREAMBLE_OVERHEAD = 70  # This stems from the 64 byte signature and the 6 bytes of unsigned shorts

    def __init__(self, signature, version, block_position, block_count, payload):
        """
        Construct a DHTBlockPayload object (which generally represents a chuck of a TrustChain block),
        which should normally be serialized and published to the DHT

        :param signature: A signature of this block's body (version + block_position + block_count + payload)
        :param version: This block's version (greater values indicate newer blocks)
        :param block_position: This chunk's position in the original block (among the other chunks)
        :param block_count: The total number of chunks in the block
        :param payload: The chunk itself
        """
        super(DHTBlockPayload, self).__init__()
        self.signature = signature
        self.version = version
        self.block_position = block_position
        self.block_count = block_count
        self.payload = payload

    def to_pack_list(self):
        return [
            ('64s', self.signature),
            ('H', self.version),
            ('H', self.block_position),
            ('H', self.block_count),
            ('raw', self.payload)
        ]

    @classmethod
    def from_unpack_list(cls, signature, version, payload, block_position, block_count):
        return DHTBlockPayload(signature, version, payload, block_position, block_count)
