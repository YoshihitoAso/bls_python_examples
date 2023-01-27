import secrets

from blspy import (
    PrivateKey,
    AugSchemeMPL,
    G1Element,
    G2Element
)

seed = secrets.token_bytes(32)
sk: PrivateKey = AugSchemeMPL.key_gen(seed)
pk: G1Element = sk.get_g1()

# print(f"sk: {sk}")
print(f"pk: {pk}")

message: bytes = bytes([1, 2, 3, 4, 5])
print(f"message: {message}")

signature: G2Element = AugSchemeMPL.sign(sk, message)
print(f"sig: {signature}")

# Verify the signature
print(AugSchemeMPL.verify(pk, message, signature))
