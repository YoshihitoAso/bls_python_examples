import secrets

from py_ecc.bls import G2ProofOfPossession as BLSPoP

seed = secrets.token_bytes(32)
sk = BLSPoP.KeyGen(seed)
pk = BLSPoP.SkToPk(sk)

# print(f"sk: {sk}")
print(f"pk: {pk}")

message: bytes = bytes([1, 2, 3, 4, 5])
print(f"message: {message}")

# Signing
signature = BLSPoP.Sign(sk, message)
print(f"sig: {signature}")

# Verifying
print(BLSPoP.Verify(pk, message, signature))
