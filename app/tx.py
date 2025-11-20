import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any

HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")  # acepta 0x + hex
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")  # 20 bytes en hex

@dataclass
class Tx:
    from_addr: str
    to: str
    value: str              # string decimal
    nonce: int              # uint64
    gas_limit: Optional[int] = None
    data_hex: Optional[str] = None
    timestamp: Optional[str] = None  # ISO8601

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "from": self.from_addr,
            "to": self.to,
            "value": self.value,
            "nonce": int(self.nonce),
        }
        if self.gas_limit is not None:
            d["gas_limit"] = int(self.gas_limit)
        if self.data_hex is not None:
            d["data_hex"] = self.data_hex
        d["timestamp"] = self.timestamp or datetime.now(timezone.utc).isoformat()
        return d


import re
_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")  # sin ceros a la izquierda

def _is_decimal_string(s: str) -> bool:
    return isinstance(s, str) and bool(_DECIMAL_RE.match(s))


def _validate_address(addr: str) -> None:
    if not isinstance(addr, str) or not ADDR_RE.match(addr):
        raise ValueError("Dirección inválida (esperado 0x + 40 hex)")


def _validate_data_hex(data_hex: Optional[str]) -> None:
    if data_hex is None:
        return
    if not isinstance(data_hex, str) or not HEX_RE.match(data_hex) or len(data_hex) % 2 != 0:
        # data_hex debe ser longitud par en hex (bytes completos)
        raise ValueError("data_hex inválido (0x + hex, longitud par)")


def create_tx(
    *,
    from_addr: str,
    to: str,
    value: str,
    nonce: int,
    gas_limit: Optional[int] = None,
    data_hex: Optional[str] = None,
    timestamp_iso: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Crea una transacción validando formato y devolviendo un dict listo para
    serializar/firmar (con JSON canónico después).
    """
    _validate_address(from_addr)
    _validate_address(to)

    if not _is_decimal_string(value):
        raise ValueError("value debe ser string decimal (ej. '1000')")

    if not isinstance(nonce, int) or nonce < 0:
        raise ValueError("nonce inválido (entero >= 0)")

    if gas_limit is not None and (not isinstance(gas_limit, int) or gas_limit <= 0):
        raise ValueError("gas_limit inválido (entero > 0)")

    _validate_data_hex(data_hex)

    tx = Tx(
        from_addr=from_addr,
        to=to,
        value=value,
        nonce=nonce,
        gas_limit=gas_limit,
        data_hex=data_hex,
        timestamp=timestamp_iso,
    )
    return tx.to_dict()