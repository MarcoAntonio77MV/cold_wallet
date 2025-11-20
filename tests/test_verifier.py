from pathlib import Path
import json
import base64

from app.keystore import create_keystore, load_keystore
from app.address import address_from_pubkey
from app.tx import create_tx
from app.signer import build_signed_tx
from app.verifier import verify_signed_tx
from app import storage


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def test_verify_ok(monkeypatch, tmp_path: Path):
    # redirige nonces.json a temporal
    monkeypatch.setattr(storage, "NONCES_PATH", tmp_path / "nonces.json")

    # prepara keystore y tx firmada
    ks = tmp_path / "keystore.json"
    create_keystore("ok", ks)
    sk = load_keystore("ok", ks)
    from_addr = address_from_pubkey(sk.verify_key.encode())

    tx = create_tx(from_addr=from_addr, to="0x" + "bb"*20, value="100", nonce=0)
    signed = build_signed_tx(sk, tx)

    ok, reason = verify_signed_tx(signed)
    assert ok and reason is None

    # nonce debe haberse actualizado
    assert storage.get_last_nonce(from_addr) == 0


def test_verify_detects_tamper(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(storage, "NONCES_PATH", tmp_path / "nonces.json")

    ks = tmp_path / "keystore.json"
    create_keystore("ok", ks)
    sk = load_keystore("ok", ks)
    from_addr = address_from_pubkey(sk.verify_key.encode())

    tx = create_tx(from_addr=from_addr, to="0x" + "bb"*20, value="100", nonce=1)
    signed = build_signed_tx(sk, tx)

    # alterar el valor de la tx (rompe la firma)
    signed["tx"]["value"] = "101"

    ok, reason = verify_signed_tx(signed)
    assert not ok and "Firma inválida" in reason


def test_verify_detects_spoofed_from(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(storage, "NONCES_PATH", tmp_path / "nonces.json")

    ks = tmp_path / "keystore.json"
    create_keystore("ok", ks)
    sk = load_keystore("ok", ks)
    real_from = address_from_pubkey(sk.verify_key.encode())

    # from MALO (no corresponde a la pubkey del firmante)
    bad_from = "0x" + "aa"*20

    # construimos la tx con 'from' malo
    tx = create_tx(from_addr=bad_from, to="0x" + "bb"*20, value="5", nonce=2)

    # firmamos MANUALMENTE el JSON canónico (sin usar build_signed_tx)
    from app.canonical_json import to_canonical_bytes
    canon = to_canonical_bytes(tx)
    sig = sk.sign(canon).signature

    import base64
    signed = {
        "tx": tx,
        "sig_scheme": "Ed25519",
        "signature_b64": base64.b64encode(sig).decode("ascii"),
        "pubkey_b64": base64.b64encode(sk.verify_key.encode()).decode("ascii"),
    }

    ok, reason = verify_signed_tx(signed)
    assert not ok and "no coincide" in reason


def test_verify_detects_replay(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(storage, "NONCES_PATH", tmp_path / "nonces.json")

    ks = tmp_path / "keystore.json"
    create_keystore("ok", ks)
    sk = load_keystore("ok", ks)
    from_addr = address_from_pubkey(sk.verify_key.encode())

    tx = create_tx(from_addr=from_addr, to="0x" + "bb"*20, value="1", nonce=7)
    signed = build_signed_tx(sk, tx)

    # Primera vez: ok
    ok, reason = verify_signed_tx(signed)
    assert ok

    # Segunda vez (mismo nonce): replay
    ok, reason = verify_signed_tx(signed)
    assert not ok and "Replay" in reason