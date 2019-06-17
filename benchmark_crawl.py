"""
Benchmark the crawls
"""
import random
import time

from ipv8.attestation.trustchain.database import TrustChainDB

big_db = TrustChainDB("/var/lib/trustchain_crawler", "trustchain")
print("Opened DB")

rand = random.Random(1)

# Get some public keys
users = []
pks = list(big_db.execute("SELECT DISTINCT public_key FROM blocks"))
pks = rand.sample(pks, 1000)

for row in pks:
    pk = row[0]
    result = list(big_db.execute("SELECT MAX(sequence_number) FROM blocks WHERE public_key = ?", (pk,)))
    max_sq = result[0][0]

    users.append((pk, max_sq))

print(users)

start_time = time.time()
for _ in xrange(5000):
    rand_user = rand.choice(users)
    rand1 = rand.randint(1, rand_user[1])
    rand2 = rand.randint(1, rand_user[1])
    if rand1 >= rand2:
        start_seq = rand2
        end_seq = rand1
    else:
        start_seq = rand1
        end_seq = rand2

    big_db.crawl(rand_user[0], start_seq, end_seq)

end_time = time.time()
print(end_time - start_time)
