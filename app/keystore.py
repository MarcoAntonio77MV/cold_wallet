import json
import os
from pathlib import Path
from typing import Tuple

from nacl.signing import SigningKey
from cryptography.exceptions import InvalidTag

from .crypto_utils import (
    b64d, b64e,
    kdf_argon2id,
    aesgcm_encrypt, aesgcm_decrypt,
    canonical_json_bytes, sha256_hex, now_iso,
)

DEFAULT_KEYSTORE_PATH = Path("app/keystore.json")


def _keystore_checksum(doc_without_checksum: dict) -> str:
    # calculamos SHA-256 del JSON canónico del documento sin el campo 'checksum'
    return sha256_hex(canonical_json_bytes(doc_without_checksum))


def create_keystore(passphrase: str, path: Path = DEFAULT_KEYSTORE_PATH) -> dict:
    """
    Genera par Ed25519, cifra la private key con AES-256-GCM bajo llave derivada con Argon2id
    y guarda un keystore.json con parámetros + checksum.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # 1) Generar llave Ed25519
    sk = SigningKey.generate()
    pk_bytes = sk.verify_key.encode()
    sk_bytes = sk.encode()

    # 2) Derivar llave simétrica desde passphrase (Argon2id)
    salt = os.urandom(32)
    kdf_params = {"salt_b64": b64e(salt), "t_cost": 3, "m_cost": 64 * 1024, "p": 1}
    key = kdf_argon2id(passphrase, salt, t_cost=kdf_params["t_cost"], m_cost=kdf_params["m_cost"], parallelism=kdf_params["p"])

    # 3) Cifrar private key con AES-256-GCM
    nonce, ct, tag = aesgcm_encrypt(key, sk_bytes)
    cipher_params = {"nonce_b64": b64e(nonce)}

    # 4) Construir documento (sin checksum primero)
    doc = {
        "kdf": "Argon2id",
        "kdf_params": kdf_params,
        "cipher": "AES-256-GCM",
        "cipher_params": cipher_params,
        "ciphertext_b64": b64e(ct),
        "tag_b64": b64e(tag),
        "pubkey_b64": b64e(pk_bytes),
        "scheme": "Ed25519",
        "created": now_iso(),
    }
    checksum = _keystore_checksum(doc)
    doc["checksum"] = checksum

    # 5) Guardar en disco
    with path.open("w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)

    return doc


def load_keystore(passphrase: str, path: Path = DEFAULT_KEYSTORE_PATH) -> SigningKey:
    """
    Carga y verifica el keystore.json, valida checksum y desencripta la private key.
    Devuelve SigningKey listo para firmar.
    """
    with path.open("r", encoding="utf-8") as f:
        doc = json.load(f)

    # 1) Verificar checksum
    doc_copy = dict(doc)
    provided_checksum = doc_copy.pop("checksum", None)
    if not provided_checksum:
        raise ValueError("Keystore sin checksum")
    computed = _keystore_checksum(doc_copy)
    if provided_checksum != computed:
        raise ValueError("Checksum inválido: posible corrupción o manipulación")

    # 2) Reconstruir KDF y AES-GCM
    kdf_params = doc["kdf_params"]
    salt = b64d(kdf_params["salt_b64"])
    key = kdf_argon2id(
        passphrase,
        salt,
        t_cost=int(kdf_params["t_cost"]),
        m_cost=int(kdf_params["m_cost"]),
        parallelism=int(kdf_params["p"]),
    )
    nonce = b64d(doc["cipher_params"]["nonce_b64"])
    ct = b64d(doc["ciphertext_b64"])
    tag = b64d(doc["tag_b64"])

    # 3) Descifrar private key
    try:
        sk_bytes = aesgcm_decrypt(key, nonce, ct, tag)
    except InvalidTag as e:
        # passphrase incorrecta o keystore alterado
        raise ValueError("No se pudo descifrar la llave privada (passphrase incorrecta o datos alterados)") from e

    # 4) Construir SigningKey
    return SigningKey(sk_bytes)