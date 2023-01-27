import secrets

from blspy import (
    PrivateKey,
    AugSchemeMPL,
    G1Element,
    G2Element
)

# Generate some more private keys
seed = secrets.token_bytes(32)
sk1: PrivateKey = AugSchemeMPL.key_gen(seed)

seed = secrets.token_bytes(32)
sk2: PrivateKey = AugSchemeMPL.key_gen(seed)

# Generate first sig
message1: bytes = bytes([1, 2, 3, 4, 5])
pk1: G1Element = sk1.get_g1()
sig1: G2Element = AugSchemeMPL.sign(sk1, message1)
print(f"sig1: {sig1}")

# Generate second sig
message2: bytes = bytes("test".encode())
pk2: G1Element = sk2.get_g1()
sig2: G2Element = AugSchemeMPL.sign(sk2, message2)
print(f"sig2: {sig2}")

# Signatures can be non-interactively combined by anyone
agg_sig: G2Element = AugSchemeMPL.aggregate([sig1, sig2])

# Verify the signature
print(AugSchemeMPL.aggregate_verify([pk1, pk2], [message1, message2], agg_sig))
