# Secure Communication Protocol (Python, macOS/ARM64)

Wallet minimal con:
- **Confidencialidad**: private key cifrada (AES-256-GCM) bajo llave derivada con **Argon2id**.
- **Integridad**: firma **Ed25519** sobre **JSON canónico**.
- **Autenticación**: `from` debe corresponder a la pubkey firmante (dirección = Keccak-256(pubkey)[-20]).

## Requisitos
- Python 3.11+ (probado en macOS M1)
- `pip`, `venv`

## Instalación
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt