import secrets

from blspy import (
    PrivateKey,
    AugSchemeMPL,
    PopSchemeMPL,
    G1Element,
    G2Element
)

# Generate some more private keys
seed = secrets.token_bytes(32)
sk1: PrivateKey = AugSchemeMPL.key_gen(seed)
pk1: G1Element = sk1.get_g1()

seed = secrets.token_bytes(32)
sk2: PrivateKey = AugSchemeMPL.key_gen(seed)
pk2: G1Element = sk2.get_g1()

seed = secrets.token_bytes(32)
sk3: PrivateKey = AugSchemeMPL.key_gen(seed)
pk3: G1Element = sk3.get_g1()

message: bytes = bytes([1, 2, 3, 4, 5])

# Generate sig
pop_sig1: G2Element = PopSchemeMPL.sign(sk1, message)
pop_sig2: G2Element = PopSchemeMPL.sign(sk2, message)
pop_sig3: G2Element = PopSchemeMPL.sign(sk3, message)

pop1: G2Element = PopSchemeMPL.pop_prove(sk1)
pop2: G2Element = PopSchemeMPL.pop_prove(sk2)
pop3: G2Element = PopSchemeMPL.pop_prove(sk3)

PopSchemeMPL.pop_verify(pk1, pop1)
PopSchemeMPL.pop_verify(pk2, pop2)
PopSchemeMPL.pop_verify(pk3, pop3)

# Aggregate signatures
pop_sig_agg: G2Element = PopSchemeMPL.aggregate([pop_sig1, pop_sig2, pop_sig3])

# Aggregate public key, indistinguishable from a single public key
pop_agg_pk: G1Element = pk1 + pk2 + pk3

# Aggregate private keys
pop_agg_sk: PrivateKey = PrivateKey.aggregate([sk1, sk2, sk3])

# Verify signature
print(PopSchemeMPL.fast_aggregate_verify([pk1, pk2, pk3], message, pop_sig_agg))  # aggregated sig

print(PopSchemeMPL.verify(pop_agg_pk, message, pop_sig_agg))  # aggregated sig & pk

if PopSchemeMPL.sign(pop_agg_sk, message) == pop_sig_agg:
    print(True)
else:
    print(False)
