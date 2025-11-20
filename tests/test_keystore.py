from pathlib import Path
import json

import pytest
from nacl.signing import SigningKey

from app.keystore import create_keystore, load_keystore


def test_create_and_load_keystore(tmp_path: Path):
    ks_path = tmp_path / "keystore.json"
    passphrase = "CorrectHorseBatteryStaple"

    doc = create_keystore(passphrase, ks_path)
    assert ks_path.exists(), "Debe crear el archivo de keystore"

    sk = load_keystore(passphrase, ks_path)
    assert isinstance(sk, SigningKey)

    # Validar que la pubkey coincide con la guardada
    pk_saved = doc["pubkey_b64"]
    assert pk_saved, "pubkey debe existir en keystore"
    assert pk_saved == __import__("base64").b64encode(sk.verify_key.encode()).decode("ascii")


def test_wrong_passphrase_fails(tmp_path: Path):
    ks_path = tmp_path / "keystore.json"
    create_keystore("mi-pass-123", ks_path)

    with pytest.raises(ValueError):
        load_keystore("pass-incorrecta", ks_path)


def test_checksum_tamper_detected(tmp_path: Path):
    ks_path = tmp_path / "keystore.json"
    create_keystore("ok", ks_path)

    # corromper el archivo: cambiar 1 char de ciphertext
    data = json.loads(ks_path.read_text(encoding="utf-8"))
    c = data["ciphertext_b64"]
    # invierte un bit (cambiar un caracter por otro válido)
    data["ciphertext_b64"] = ("A" if c[0] != "A" else "B") + c[1:]
    ks_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="Checksum inválido"):
        load_keystore("ok", ks_path)