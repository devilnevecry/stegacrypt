"""Интерфейс командной строки."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, core, stego
from .errors import KeyFileError, PassphraseRequired, StegacryptError
from .keys import DEFAULT_KEY_BITS, MIN_KEY_BITS, generate_keypair

PASSPHRASE_ENV = "STEGACRYPT_PASSPHRASE"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegacrypt",
        description="Шифрует сообщение открытым ключом получателя и прячет его в PNG.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="команда")

    keygen = sub.add_parser("keygen", help="создать пару RSA-ключей")
    keygen.add_argument("name", help="имя владельца, например alice")
    keygen.add_argument(
        "--bits",
        type=int,
        default=DEFAULT_KEY_BITS,
        help=f"размер ключа (по умолчанию {DEFAULT_KEY_BITS}, минимум {MIN_KEY_BITS})",
    )
    keygen.add_argument("--out-dir", default=".", help="куда сохранить ключи (по умолчанию .)")
    keygen.add_argument(
        "--no-passphrase",
        action="store_true",
        help="не защищать закрытый ключ паролем (небезопасно)",
    )
    keygen.add_argument("--force", action="store_true", help="перезаписать существующие ключи")

    enc = sub.add_parser("encrypt", help="зашифровать сообщение и спрятать его в изображении")
    enc.add_argument("-i", "--image", required=True, help="исходное изображение")
    enc.add_argument("-k", "--key", required=True, help="открытый ключ получателя (*_public.key)")
    enc.add_argument("-o", "--out", required=True, help="куда сохранить результат (.png)")
    src = enc.add_mutually_exclusive_group()
    src.add_argument("-m", "--message", help="текст сообщения")
    src.add_argument("-f", "--message-file", help="прочитать сообщение из файла")
    enc.add_argument("--force", action="store_true", help="перезаписать выходной файл")

    dec = sub.add_parser("decrypt", help="достать сообщение из изображения")
    dec.add_argument("-i", "--image", required=True, help="изображение с сообщением")
    dec.add_argument("-k", "--key", required=True, help="ваш закрытый ключ (*_private.key)")
    dec.add_argument("-o", "--out", help="записать сообщение в файл вместо вывода на экран")
    dec.add_argument("--force", action="store_true", help="перезаписать выходной файл")

    cap = sub.add_parser("capacity", help="сколько данных поместится в изображение")
    cap.add_argument("image", help="изображение")
    cap.add_argument("-k", "--key", help="открытый ключ: показать размер самого сообщения")
    return parser


def _passphrase_from_env() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV)
    return value.encode() if value else None


def _new_passphrase() -> bytes:
    env = _passphrase_from_env()
    if env:
        return env
    first = getpass.getpass("Пароль для закрытого ключа: ")
    if not first:
        raise KeyFileError("Пустой пароль. Если ключ не нужно защищать, используйте --no-passphrase.")
    if getpass.getpass("Повторите пароль: ") != first:
        raise KeyFileError("Пароли не совпали.")
    return first.encode()


def _cmd_keygen(args: argparse.Namespace) -> int:
    passphrase = None if args.no_passphrase else _new_passphrase()
    private, public = generate_keypair(
        args.name, args.out_dir, bits=args.bits, passphrase=passphrase, force=args.force
    )
    print(f"Закрытый ключ (никому не показывайте): {private}")
    print(f"Открытый ключ (его можно отправлять):  {public}")
    if passphrase is None:
        print("Внимание: закрытый ключ не защищён паролем.", file=sys.stderr)
    return 0


def _read_message(args: argparse.Namespace) -> bytes:
    if args.message is not None:
        data = args.message.encode()
    elif args.message_file:
        try:
            data = Path(args.message_file).read_bytes()
        except OSError as exc:
            raise StegacryptError(
                f"Не удалось прочитать {args.message_file}: {exc.strerror or exc}"
            ) from exc
    elif not sys.stdin.isatty():
        data = sys.stdin.buffer.read()
    else:
        data = input("Сообщение: ").encode()
    if not data:
        raise StegacryptError("Сообщение пустое.")
    return data


def _cmd_encrypt(args: argparse.Namespace) -> int:
    message = _read_message(args)
    size = core.hide(args.image, args.key, message, args.out, force=args.force)
    print(f"Готово: {len(message)} байт сообщения спрятано в {args.out} (в изображении {size} байт).")
    print("Отправляйте файл как есть: мессенджеры, которые пережимают картинки, разрушают данные.")
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    try:
        data = core.reveal(args.image, args.key, _passphrase_from_env())
    except PassphraseRequired:
        passphrase = getpass.getpass(f"Пароль для {args.key}: ")
        data = core.reveal(args.image, args.key, passphrase.encode())

    if args.out:
        out = Path(args.out)
        if out.exists() and not args.force:
            raise StegacryptError(f"Файл {out} уже существует. Добавьте --force.")
        out.write_bytes(data)
        print(f"Сообщение ({len(data)} байт) сохранено в {out}")
        return 0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise StegacryptError(
            "Сообщение не является текстом UTF-8. Сохраните его в файл через -o."
        ) from None
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    return 0


def _cmd_capacity(args: argparse.Namespace) -> int:
    img = stego.open_image(args.image)
    print(f"Размер: {img.size[0]}x{img.size[1]}")
    print(f"Вместимость: {stego.capacity(img.size)} байт")
    if args.key:
        print(f"Максимальное сообщение для этого ключа: {core.max_message_size(args.image, args.key)} байт")
    return 0


_COMMANDS = {
    "keygen": _cmd_keygen,
    "encrypt": _cmd_encrypt,
    "decrypt": _cmd_decrypt,
    "capacity": _cmd_capacity,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except StegacryptError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nПрервано.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
