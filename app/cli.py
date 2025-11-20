import argparse
import json
from pathlib import Path
from getpass import getpass

from .keystore import create_keystore, load_keystore, DEFAULT_KEYSTORE_PATH
from .address import address_from_pubkey
from .tx import create_tx
from .signer import build_signed_tx, save_signed_tx
from .verifier import verify_file, VERIFIED_DIR


def _read_passphrase(prompt: str = "Passphrase: ") -> str:
    pw = getpass(prompt)
    if not pw:
        raise SystemExit("Passphrase vacía; operación cancelada.")
    return pw


def cmd_wallet_init(args: argparse.Namespace) -> None:
    path = Path(args.path) if args.path else DEFAULT_KEYSTORE_PATH
    if path.exists() and not args.force:
        raise SystemExit(f"Ya existe {path}. Usa --force para sobrescribir (¡cuidado!).")
    passphrase = _read_passphrase("Nueva passphrase: ")
    confirm = _read_passphrase("Confirma passphrase: ")
    if passphrase != confirm:
        raise SystemExit("Las passphrases no coinciden.")
    doc = create_keystore(passphrase, path)
    print(f"Keystore creado en: {path}")
    print(f"Esquema: {doc['scheme']}")
    print(f"Public key (b64): {doc['pubkey_b64']}")


def cmd_wallet_address(args: argparse.Namespace) -> None:
    path = Path(args.path) if args.path else DEFAULT_KEYSTORE_PATH
    passphrase = _read_passphrase()
    sk = load_keystore(passphrase, path)
    pk = sk.verify_key.encode()
    addr = address_from_pubkey(pk)
    print("Address:", addr)
    print("Public key (hex):", pk.hex())


def cmd_wallet_sign(args: argparse.Namespace) -> None:
    ks_path = Path(args.keystore) if args.keystore else DEFAULT_KEYSTORE_PATH
    passphrase = _read_passphrase()
    sk = load_keystore(passphrase, ks_path)
    from_addr = address_from_pubkey(sk.verify_key.encode())

    tx = create_tx(
        from_addr=from_addr,
        to=args.to,
        value=args.value,
        nonce=int(args.nonce),
        gas_limit=int(args.gas_limit) if args.gas_limit else None,
        data_hex=args.data_hex,
    )

    signed = build_signed_tx(sk, tx)
    outdir = Path(args.outdir) if args.outdir else Path("outbox")
    path = save_signed_tx(signed, outdir)
    print("Transacción firmada guardada en:", path)


def cmd_wallet_recv(args: argparse.Namespace) -> None:
    path = Path(args.path)
    if not path.exists():
        raise SystemExit(f"No existe: {path}")
    ok, reason, dest = verify_file(path, move_on_success=not args.no_move)
    if ok:
        print("VALID ✅")
        if dest:
            print("Copiada a:", dest)
        else:
            print(f"Manteniendo el archivo en: {path}")
    else:
        print("INVALID ❌ -", reason)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wallet", description="Secure Communication Protocol CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # wallet init
    sp = sub.add_parser("init", help="Crear un keystore nuevo")
    sp.add_argument("--path", help="Ruta del keystore (default: app/keystore.json)")
    sp.add_argument("--force", action="store_true", help="Sobrescribir si existe")
    sp.set_defaults(func=cmd_wallet_init)

    # wallet address
    sp = sub.add_parser("address", help="Mostrar address y pubkey")
    sp.add_argument("--path", help="Ruta del keystore (default: app/keystore.json)")
    sp.set_defaults(func=cmd_wallet_address)

    # wallet sign
    sp = sub.add_parser("sign", help="Firmar una transacción y guardarla en outbox/")
    sp.add_argument("--to", required=True, help="Dirección destino (0x + 40 hex)")
    sp.add_argument("--value", required=True, help="Monto como string decimal (ej. '1000')")
    sp.add_argument("--nonce", required=True, help="Nonce entero >= 0")
    sp.add_argument("--gas-limit", help="Gas opcional (entero > 0)")
    sp.add_argument("--data-hex", help="Payload opcional (0x... hex longitud par)")
    sp.add_argument("--keystore", help="Ruta del keystore (default: app/keystore.json)")
    sp.add_argument("--outdir", help="Directorio de salida (default: outbox/)")
    sp.set_defaults(func=cmd_wallet_sign)

    # wallet recv
    sp = sub.add_parser("recv", help="Verificar un archivo firmado")
    sp.add_argument("--path", required=True, help="Ruta al JSON firmado (ej. inbox/tx_0.json)")
    sp.add_argument("--no-move", action="store_true", help="No copiar a verified/ aunque sea válido")
    sp.set_defaults(func=cmd_wallet_recv)

    return p


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()