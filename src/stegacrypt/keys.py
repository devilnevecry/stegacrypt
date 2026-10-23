"""Генерация и загрузка RSA-ключей."""

from __future__ import annotations

import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .errors import KeyFileError, PassphraseRequired

MIN_KEY_BITS = 2048
DEFAULT_KEY_BITS = 3072

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def validate_name(name: str) -> str:
    """Имя используется в именах файлов, поэтому пути и спецсимволы запрещены."""
    if not _NAME_RE.match(name):
        raise KeyFileError(
            f"Недопустимое имя '{name}': разрешены латиница, цифры, '.', '_' и '-', "
            "первым должна быть буква или цифра."
        )
    return name


def key_paths(name: str, out_dir: str | os.PathLike = ".") -> tuple[Path, Path]:
    """Пути к закрытому и открытому ключам для имени ``name``."""
    validate_name(name)
    base = Path(out_dir)
    return base / f"{name}_private.key", base / f"{name}_public.key"


def generate_keypair(
    name: str,
    out_dir: str | os.PathLike = ".",
    bits: int = DEFAULT_KEY_BITS,
    passphrase: bytes | None = None,
    force: bool = False,
) -> tuple[Path, Path]:
    """Создать пару ключей и записать её в ``out_dir``.

    Закрытый ключ шифруется паролем, если он передан, и получает права 0600.
    Существующие файлы не перезаписываются без ``force``.
    """
    if bits < MIN_KEY_BITS:
        raise KeyFileError(f"Размер ключа должен быть не меньше {MIN_KEY_BITS} бит.")
    private_path, public_path = key_paths(name, out_dir)
    if not force:
        for path in (private_path, public_path):
            if path.exists():
                raise KeyFileError(
                    f"Файл {path} уже существует. Добавьте --force, чтобы перезаписать."
                )
    if not private_path.parent.is_dir():
        raise KeyFileError(f"Каталог {private_path.parent} не существует.")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(private_path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_pem)
    os.chmod(private_path, 0o600)  # если файл уже существовал (--force)
    public_path.write_bytes(public_pem)
    return private_path, public_path


def _read(path: str | os.PathLike) -> bytes:
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        raise KeyFileError(f"Файл ключа не найден: {path}") from None
    except OSError as exc:
        raise KeyFileError(f"Не удалось прочитать {path}: {exc.strerror or exc}") from exc


def _check_size(key: rsa.RSAPublicKey | rsa.RSAPrivateKey, path: str | os.PathLike) -> None:
    if key.key_size < MIN_KEY_BITS:
        raise KeyFileError(
            f"Ключ {path} слишком слабый ({key.key_size} бит, нужно не меньше {MIN_KEY_BITS})."
        )


def load_public_key(path: str | os.PathLike) -> rsa.RSAPublicKey:
    """Загрузить открытый RSA-ключ в формате PEM."""
    data = _read(path)
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise KeyFileError(
            f"{path} не похож на открытый ключ. Нужен файл *_public.key."
        ) from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyFileError(f"{path}: поддерживаются только RSA-ключи.")
    _check_size(key, path)
    return key


def is_encrypted(path: str | os.PathLike) -> bool:
    """Защищён ли закрытый ключ паролем."""
    return b"ENCRYPTED" in _read(path)


def load_private_key(
    path: str | os.PathLike, passphrase: bytes | None = None
) -> rsa.RSAPrivateKey:
    """Загрузить закрытый RSA-ключ; для защищённых ключей нужен ``passphrase``."""
    data = _read(path)
    encrypted = b"ENCRYPTED" in data
    if encrypted and not passphrase:
        raise PassphraseRequired(f"Ключ {path} защищён паролем.")
    try:
        key = serialization.load_pem_private_key(
            data, password=passphrase if encrypted else None
        )
    except (ValueError, TypeError) as exc:
        if encrypted:
            raise KeyFileError("Неверный пароль или повреждённый ключ.") from exc
        raise KeyFileError(
            f"{path} не похож на закрытый ключ. Нужен файл *_private.key."
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyFileError(f"{path}: поддерживаются только RSA-ключи.")
    _check_size(key, path)
    return key
