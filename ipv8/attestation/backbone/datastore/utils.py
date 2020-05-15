from binascii import hexlify

KEY_LEN = 8


def key_to_id(key):
    return hexlify(key)[-KEY_LEN:].decode()


def id_to_int(id):
    return int(id, 16)


def int_to_id(int_val):
    val = hex(int_val)[2:]
    while len(val) < KEY_LEN:
        val = "0" + val
    return val


def decode_frontier(frontier: dict):
    """
    Decode for packet
    """
    decoded = dict()
    for k, v in frontier:
        if k == 'h':
            decoded[k] = v
        else:
            decoded[k] = decode_links(v)
    return decoded


def encode_frontier(frontier):
    """
    Encode to python dict
    """
    encoded = dict()
    for k, v in frontier:
        if k == 'h':
            encoded[k] = v
        else:
            encoded[k] = encode_links(v)
    return encoded


def decode_links(link_val):
    if type(link_val) == set:
        # set of tuples: seq_num, hash
        res = list()
        if link_val:
            for s, h in link_val:
                h_val = h.decode('utf-8') if type(h) == bytes else h
                res.append((int(s), h_val))
        return res
    else:
        return link_val


def encode_links(link_val):
    res = set()
    if not link_val:
        return res
    for s, h in link_val:
        res.add((int(s), h))
    return res


def expand_ranges(range_vals):
    val_set = set()
    for b, e in range_vals:
        for val in range(b, e + 1):
            val_set.add(val)
    return val_set


def ranges(nums):
    nums = sorted(nums)
    gaps = [[s, e] for s, e in zip(nums, nums[1:]) if s + 1 < e]
    edges = iter(nums[:1] + sum(gaps, []) + nums[-1:])
    return list(zip(edges, edges))
