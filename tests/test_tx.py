import pytest
from app.tx import create_tx
from app.storage import get_last_nonce, set_last_nonce

def test_create_tx_minimal_ok():
    tx = create_tx(
        from_addr="0x" + "aa"*20,
        to="0x" + "bb"*20,
        value="1000",
        nonce=0,
    )
    assert tx["from"].startswith("0x") and tx["to"].startswith("0x")
    assert tx["value"] == "1000"
    assert isinstance(tx["nonce"], int)
    assert "timestamp" in tx

def test_create_tx_with_options_ok():
    tx = create_tx(
        from_addr="0x" + "11"*20,
        to="0x" + "22"*20,
        value="42",
        nonce=7,
        gas_limit=21000,
        data_hex="0xdeadbeef",
    )
    assert tx["gas_limit"] == 21000
    assert tx["data_hex"] == "0xdeadbeef"

@pytest.mark.parametrize("bad_addr", ["0x123", "abc", "0x"+"zz"*20])
def test_bad_addresses_fail(bad_addr):
    with pytest.raises(ValueError):
        create_tx(from_addr=bad_addr, to="0x" + "aa"*20, value="1", nonce=0)
    with pytest.raises(ValueError):
        create_tx(from_addr="0x" + "aa"*20, to=bad_addr, value="1", nonce=0)

@pytest.mark.parametrize("bad_value", ["", "01", "1.0", 100, "-1"])
def test_bad_value_fails(bad_value):
    with pytest.raises(ValueError):
        create_tx(from_addr="0x" + "aa"*20, to="0x" + "bb"*20, value=bad_value, nonce=0)

def test_nonce_tracker_roundtrip(tmp_path, monkeypatch):
    # redirige el archivo nonces.json temporalmente
    from app import storage
    monkeypatch.setattr(storage, "NONCES_PATH", tmp_path / "nonces.json")

    addr = "0x" + "cc"*20
    assert storage.get_last_nonce(addr) == -1
    storage.set_last_nonce(addr, 5)
    assert storage.get_last_nonce(addr) == 5