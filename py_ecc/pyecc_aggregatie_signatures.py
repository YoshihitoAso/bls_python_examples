import secrets

from py_ecc.bls import G2ProofOfPossession as BLSPoP

# Generate some more private keys
seed = secrets.token_bytes(32)
sk1 = BLSPoP.KeyGen(seed)

seed = secrets.token_bytes(32)
sk2 = BLSPoP.KeyGen(seed)

message: bytes = bytes([1, 2, 3, 4, 5])

# Generate first sig
pk1 = BLSPoP.SkToPk(sk1)
sig1 = BLSPoP.Sign(sk1, message)
print(f"sig1: {sig1}")

# Generate second sig
pk2 = BLSPoP.SkToPk(sk2)
sig2 = BLSPoP.Sign(sk2, message)
print(f"sig2: {sig2}")

# Aggregating
agg_sig = BLSPoP.Aggregate([sig1, sig2])

# Verifying signatures over the same message.
print(BLSPoP.FastAggregateVerify([pk1, pk2], message, agg_sig))
