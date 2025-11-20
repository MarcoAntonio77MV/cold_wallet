from nacl.signing import SigningKey
from app.address import address_from_pubkey

def test_address_deterministic_and_format():
    sk = SigningKey.generate()
    pk = sk.verify_key.encode()
    a1 = address_from_pubkey(pk)
    a2 = address_from_pubkey(pk)
    assert a1 == a2
    assert a1.startswith("0x") and len(a1) == 42  # 0x + 40 hex chars

def test_address_changes_if_pubkey_changes():
    sk = SigningKey.generate()
    pk = bytearray(sk.verify_key.encode())
    a1 = address_from_pubkey(bytes(pk))
    pk[0] ^= 0x01   # cambia 1 bit
    a2 = address_from_pubkey(bytes(pk))
    assert a1 != a2