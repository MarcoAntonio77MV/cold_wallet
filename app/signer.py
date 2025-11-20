import json
from pathlib import Path
from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError

from .canonical_json import to_canonical_bytes
from .crypto_utils import b64e
from .address import address_from_pubkey

OUTBOX_DIR = Path("outbox")


def build_signed_tx(sk: SigningKey, tx: dict) -> dict:
    """
    Firma los bytes canónicos de 'tx' con Ed25519 y regresa el paquete:
    { "tx", "sig_scheme", "signature_b64", "pubkey_b64" }

    También valida que tx["from"] coincida con la pubkey del firmante.
    """
    if "from" not in tx:
        raise ValueError("tx sin campo 'from'")

    pubkey_bytes = sk.verify_key.encode()
    derived_addr = address_from_pubkey(pubkey_bytes)
    if tx["from"] != derived_addr:
        raise ValueError("La dirección 'from' no coincide con la clave del firmante")

    canon = to_canonical_bytes(tx)
    sig = sk.sign(canon).signature  # 64 bytes

    signed = {
        "tx": tx,
        "sig_scheme": "Ed25519",
        "signature_b64": b64e(sig),
        "pubkey_b64": b64e(pubkey_bytes),
    }
    return signed


def save_signed_tx(signed: dict, outdir: Path = OUTBOX_DIR) -> Path:
    """
    Guarda el paquete firmado como JSON en outbox/tx_<nonce>.json y regresa la ruta.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    nonce = signed["tx"]["nonce"]
    path = outdir / f"tx_{nonce}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2, ensure_ascii=False)
    return path