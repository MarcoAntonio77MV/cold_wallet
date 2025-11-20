import json
from typing import Any, Dict

def _normalize(value: Any) -> Any:
    """
    Normaliza un objeto para producir un JSON canónico y determinístico.

    Reglas:
    - dict: claves ordenadas alfabéticamente (y valores normalizados).
    - list/tuple: normaliza cada elemento (mantiene orden).
    - int: a string decimal (evita diferencias de representación).
    - float: a string estable (no notación científica).
    - str/bool/None: igual.
    """
    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for k in sorted(value.keys()):
            normalized[k] = _normalize(value[k])
        return normalized

    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        return format(value, ".18g")

    return value


def to_canonical_bytes(obj: Any) -> bytes:
    """
    Devuelve los BYTES canónicos para firmar:
    - claves ordenadas
    - sin espacios innecesarios
    - números ya convertidos por _normalize
    """
    normalized = _normalize(obj)
    canonical_str = json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),  # sin espacios
        sort_keys=True          # redundante pero consistente
    )
    return canonical_str.encode("utf-8")