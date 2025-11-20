from Crypto.Hash import keccak

def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def address_from_pubkey(pubkey_bytes: bytes) -> str:
    """
    Deriva la dirección a partir de la clave pública (Ed25519 verify_key bytes).
    Formato: '0x' + 40 hex (20 bytes).
    """
    digest = keccak256(pubkey_bytes)   # 32 bytes
    addr_bytes = digest[-20:]          # últimos 20 bytes
    return "0x" + addr_bytes.hex()