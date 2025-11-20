import json
from pathlib import Path
import base64
from typing import Tuple, Optional

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from .canonical_json import to_canonical_bytes
from .address import address_from_pubkey
from .storage import get_last_nonce, set_last_nonce

INBOX_DIR = Path("inbox")
VERIFIED_DIR = Path("verified")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def verify_signed_tx(signed: dict) -> Tuple[bool, Optional[str]]:
    """
    Verifica un paquete firmado con formato:
    {
      "tx": {...},
      "sig_scheme": "Ed25519",
      "signature_b64": "...",
      "pubkey_b64": "..."
    }

    Retorna (True, None) si es válido; de lo contrario (False, "razón").
    Si es válido, ACTUALIZA el nonce en almacenamiento para prevenir replay.
    """
    # 1) Validar estructura mínima
    try:
        tx = signed["tx"]
        scheme = signed["sig_scheme"]
        sig = _b64d(signed["signature_b64"])
        pub = _b64d(signed["pubkey_b64"])
    except Exception:
        return False, "Paquete incompleto o malformado"

    if scheme != "Ed25519":
        return False, "Esquema de firma no soportado"

    # 2) Recalcular canónico y verificar firma
    canon = to_canonical_bytes(tx)
    try:
        vk = VerifyKey(pub)
        vk.verify(canon, sig)
    except BadSignatureError:
        return False, "Firma inválida"

    # 3) Address debe coincidir con 'from'
    derived_addr = address_from_pubkey(pub)
    if tx.get("from") != derived_addr:
        return False, "La dirección 'from' no coincide con la pubkey firmante"

    # 4) Checar nonce (anti-replay)
    from_addr = tx["from"]
    nonce = tx.get("nonce")
    if not isinstance(nonce, int):
        return False, "Nonce inválido"

    last = get_last_nonce(from_addr)  # -1 si no existe
    if nonce <= last:
        return False, f"Replay detectado (nonce {nonce} <= último {last})"

    # 5) Si todo ok, actualiza nonce
    set_last_nonce(from_addr, nonce)
    return True, None


def verify_file(path: Path, *, move_on_success: bool = True) -> Tuple[bool, Optional[str], Optional[Path]]:
    """
    Abre un archivo JSON firmado (por ejemplo, en ./inbox), y lo verifica.
    Si es válido y move_on_success=True, lo copia a ./verified/ y regresa la ruta destino.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, "No es un JSON válido", None

    ok, reason = verify_signed_tx(data)
    if not ok:
        return False, reason, None

    dest = None
    if move_on_success:
        VERIFIED_DIR.mkdir(parents=True, exist_ok=True)
        dest = VERIFIED_DIR / path.name
        dest.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return True, None, dest