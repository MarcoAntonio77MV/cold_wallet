import json
from pathlib import Path
from typing import Dict

NONCES_PATH = Path("nonces.json")  # lo ignoramos en .gitignore

def _load_json(path: Path) -> Dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8") or "{}")

def _save_json(path: Path, data: Dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def get_last_nonce(address: str) -> int:
    """
    Regresa el último nonce visto para 'address'. Si no existe, -1.
    """
    data = _load_json(NONCES_PATH)
    return int(data.get(address, -1))

def set_last_nonce(address: str, nonce: int) -> None:
    """
    Actualiza el último nonce visto para 'address'.
    """
    data = _load_json(NONCES_PATH)
    data[address] = int(nonce)
    _save_json(NONCES_PATH, data)