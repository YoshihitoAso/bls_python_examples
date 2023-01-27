import secrets

from py_ecc.bls import G2ProofOfPossession as BLSPoP

# Generate some more private keys
seed = secrets.token_bytes(32)
sk1 = BLSPoP.KeyGen(seed)

seed = secrets.token_bytes(32)
sk2 = BLSPoP.KeyGen(seed)

# Generate first sig
message1: bytes = bytes([1, 2, 3, 4, 5])
pk1 = BLSPoP.SkToPk(sk1)
sig1 = BLSPoP.Sign(sk1, message1)
print(f"sig1: {sig1}")

# Generate second sig
message2: bytes = bytes("test".encode())
pk2 = BLSPoP.SkToPk(sk2)
sig2 = BLSPoP.Sign(sk2, message2)
print(f"sig2: {sig2}")

# Aggregating
agg_sig = BLSPoP.Aggregate([sig1, sig2])
print(f"agg_sig: {agg_sig}")

# Verify aggregate signature with different messages
print(BLSPoP.AggregateVerify([pk1, pk2], [message1, message2], agg_sig))
