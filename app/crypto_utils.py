import base64
import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ====== helpers de base64 ======
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ====== Argon2id KDF ======
def kdf_argon2id(
    passphrase: str,
    salt: bytes,
    *,
    t_cost: int = 3,          # iteraciones
    m_cost: int = 64 * 1024,  # memoria en KiB (64 MiB)
    parallelism: int = 1,
    key_len: int = 32,        # 256-bit key
) -> bytes:
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("Salt inválida (min 16 bytes)")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=parallelism,
        hash_len=key_len,
        type=Type.ID,
    )


# ====== AES-256-GCM ======
def aesgcm_encrypt(key: bytes, plaintext: bytes, *, aad: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    Devuelve (nonce, ciphertext, tag). cryptography.AESGCM concatena tag al final,
    aquí la separamos para guardarla por campo.
    """
    if len(key) != 32:
        raise ValueError("AESGCM requiere llave de 32 bytes (256-bit)")
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct_with_tag = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct_with_tag[:-16], ct_with_tag[-16:]

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, *, aad: Optional[bytes] = None) -> bytes:
    if len(key) != 32:
        raise ValueError("AESGCM requiere llave de 32 bytes (256-bit)")
    aes = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aes.decrypt(nonce, ct_with_tag, aad)


# ====== checksum canónico del keystore ======
def canonical_json_bytes(obj) -> bytes:
    # evitemos dependencias circulares: json canónico minimalista para el keystore
    import json
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()