from __future__ import absolute_import

from ...messaging.payload import Payload


class PeerCrawlRequestPayload(Payload):
    """
    Request a crawl that will estimate the balance of a peer that is not older than some seq_num
    """

    format_list = ['l', 'Q', 'varlenI']

    def __init__(self, seq_num, crawl_id, pack_except):
        super(PeerCrawlRequestPayload, self).__init__()
        self.seq_num = seq_num
        self.crawl_id = crawl_id
        self.pack_except = pack_except

    def to_pack_list(self):
        data = [('l', self.seq_num),
                ('Q', self.crawl_id),
                ('varlenI', self.pack_except)]

        return data

    @classmethod
    def from_unpack_list(cls, seq_num, crawl_id, pack_except):
        return PeerCrawlRequestPayload(seq_num, crawl_id, pack_except)


class PeerCrawlResponsePayload(Payload):
    """
    Request a crawl that will estimate the balance of a peer that is not older than some seq_num
    """

    format_list = ['Q', 'varlenI']

    def __init__(self, crawl_id, chain):
        super(PeerCrawlResponsePayload, self).__init__()
        self.crawl_id = crawl_id
        self.chain = chain

    def to_pack_list(self):
        data = [('Q', self.crawl_id),
                ('varlenI', self.chain)]

        return data

    @classmethod
    def from_unpack_list(cls, crawl_id, chain):
        return PeerCrawlResponsePayload(crawl_id, chain)
