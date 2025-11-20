from app.canonical_json import to_canonical_bytes

def test_same_dict_same_output():
    tx1 = {"from": "0xABC", "to": "0xDEF", "value": "1000", "nonce": 5}
    tx2 = {"nonce": 5, "value": "1000", "to": "0xDEF", "from": "0xABC"}
    b1 = to_canonical_bytes(tx1)
    b2 = to_canonical_bytes(tx2)
    assert b1 == b2, "El orden de entrada no debe afectar el resultado"

def test_number_is_stringified():
    tx = {"nonce": 5}
    out_bytes = to_canonical_bytes(tx)
    assert b'"nonce":"5"' in out_bytes  # debe ser string, no número

def test_change_value_changes_bytes():
    base = {"from": "0xA", "to": "0xB", "value": "10", "nonce": 1}
    mod  = {"from": "0xA", "to": "0xB", "value": "11", "nonce": 1}
    b1 = to_canonical_bytes(base)
    b2 = to_canonical_bytes(mod)
    assert b1 != b2, "Cambiar la tx debe cambiar los bytes canónicos"