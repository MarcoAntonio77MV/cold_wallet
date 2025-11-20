from pathlib import Path
import base64
import json

import pytest
from nacl.signing import SigningKey, VerifyKey

from app.keystore import create_keystore, load_keystore
from app.address import address_from_pubkey
from app.tx import create_tx
from app.signer import build_signed_tx, save_signed_tx
from app.canonical_json import to_canonical_bytes


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def test_build_signed_tx_and_verify(tmp_path: Path):
    # crea keystore temporal
    ks_path = tmp_path / "keystore.json"
    passphrase = "pass123"
    doc = create_keystore(passphrase, ks_path)
    sk = load_keystore(passphrase, ks_path)

    # address a partir de la pubkey del keystore
    pk_bytes = sk.verify_key.encode()
    from_addr = address_from_pubkey(pk_bytes)

    # crear tx mínima válida
    tx = create_tx(
        from_addr=from_addr,
        to="0x" + "bb"*20,
        value="1000",
        nonce=0,
    )

    signed = build_signed_tx(sk, tx)
    assert signed["sig_scheme"] == "Ed25519"
    assert "signature_b64" in signed and "pubkey_b64" in signed

    # Verificar la firma manualmente con VerifyKey (sin el verificador aún)
    canon = to_canonical_bytes(tx)
    sig = _b64d(signed["signature_b64"])
    pub = _b64d(signed["pubkey_b64"])
    vk = VerifyKey(pub)
    # si es inválida, lanzaría BadSignatureError
    vk.verify(canon, sig)


def test_build_signed_tx_rejects_wrong_from(tmp_path: Path):
    ks_path = tmp_path / "keystore.json"
    create_keystore("ok", ks_path)
    sk = load_keystore("ok", ks_path)

    # from_addr incorrecta (no coincide con pubkey)
    tx = create_tx(
        from_addr="0x" + "aa"*20,
        to="0x" + "bb"*20,
        value="1",
        nonce=1,
    )

    with pytest.raises(ValueError, match="no coincide"):
        build_signed_tx(sk, tx)


def test_save_signed_tx_writes_file(tmp_path: Path):
    ks_path = tmp_path / "keystore.json"
    create_keystore("ok", ks_path)
    sk = load_keystore("ok", ks_path)

    from_addr = address_from_pubkey(sk.verify_key.encode())
    tx = create_tx(from_addr=from_addr, to="0x" + "bb"*20, value="7", nonce=9)
    signed = build_signed_tx(sk, tx)

    outdir = tmp_path / "outbox"
    p = save_signed_tx(signed, outdir)
    assert p.exists()
    saved = json.loads(p.read_text(encoding="utf-8"))
    assert saved["tx"]["nonce"] == 9
    assert saved["sig_scheme"] == "Ed25519"