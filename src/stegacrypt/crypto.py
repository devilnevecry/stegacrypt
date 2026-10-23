"""Гибридное шифрование: AES-256-GCM для текста, RSA-OAEP для ключа AES.

Чистый RSA-OAEP не умеет шифровать больше ~190 байт (для ключа 2048 бит),
поэтому сообщение шифруется случайным ключом AES, а уже этот ключ —
открытым ключом получателя.

Формат полезной нагрузки (все числа big-endian)::

    "SGC" | версия (1 байт) | длина обёрнутого ключа (2 байта)
    | обёрнутый ключ AES | nonce (12 байт) | шифртекст + тег GCM

Всё, что стоит перед nonce, передаётся в GCM как AAD, поэтому подмена
заголовка или обёрнутого ключа обнаруживается при расшифровке.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError, NoMessageError

MAGIC = b"SGC"
VERSION = 1
NONCE_SIZE = 12
TAG_SIZE = 16
_PREFIX = len(MAGIC) + 1 + 2  # магия + версия + длина обёрнутого ключа


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def overhead(key_bits: int) -> int:
    """Сколько байт полезной нагрузки занимает служебная информация."""
    return _PREFIX + key_bits // 8 + NONCE_SIZE + TAG_SIZE


def encrypt(message: bytes, public_key: RSAPublicKey) -> bytes:
    """Зашифровать ``message`` для владельца ``public_key``."""
    aes_key = AESGCM.generate_key(bit_length=256)
    wrapped = public_key.encrypt(aes_key, _oaep())
    header = MAGIC + bytes([VERSION]) + len(wrapped).to_bytes(2, "big") + wrapped
    nonce = os.urandom(NONCE_SIZE)
    return header + nonce + AESGCM(aes_key).encrypt(nonce, message, header)


def decrypt(payload: bytes, private_key: RSAPrivateKey) -> bytes:
    """Расшифровать ``payload`` закрытым ключом."""
    if len(payload) < _PREFIX or payload[: len(MAGIC)] != MAGIC:
        raise NoMessageError("В изображении нет сообщения stegacrypt.")
    if payload[len(MAGIC)] != VERSION:
        raise DecryptionError(
            f"Неподдерживаемая версия формата: {payload[len(MAGIC)]} "
            f"(эта программа понимает версию {VERSION})."
        )

    wrapped_len = int.from_bytes(payload[len(MAGIC) + 1 : _PREFIX], "big")
    header_end = _PREFIX + wrapped_len
    if len(payload) < header_end + NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("Данные в изображении повреждены или обрезаны.")
    if wrapped_len != private_key.key_size // 8:
        raise DecryptionError(
            "Сообщение зашифровано другим ключом (не совпадает размер ключа)."
        )

    header = payload[:header_end]
    nonce = payload[header_end : header_end + NONCE_SIZE]
    ciphertext = payload[header_end + NONCE_SIZE :]
    try:
        aes_key = private_key.decrypt(header[_PREFIX:], _oaep())
        return AESGCM(aes_key).decrypt(nonce, ciphertext, header)
    except (ValueError, InvalidTag) as exc:
        raise DecryptionError(
            "Не удалось расшифровать: неверный ключ либо данные в изображении "
            "повреждены (например, картинку пересжали)."
        ) from exc
