"""Высокоуровневые операции: спрятать и достать сообщение."""

from __future__ import annotations

import os
from pathlib import Path

from . import crypto, stego
from .errors import ImageError
from .keys import load_private_key, load_public_key


def hide(
    image_path: str | os.PathLike,
    public_key_path: str | os.PathLike,
    message: bytes,
    out_path: str | os.PathLike,
    force: bool = False,
) -> int:
    """Зашифровать ``message`` и спрятать его в копии изображения.

    Возвращает размер спрятанной нагрузки в байтах. Результат всегда PNG.
    """
    if Path(out_path).suffix.lower() != ".png":
        raise ImageError(
            "Результат нужно сохранять в .png: JPEG и другие форматы с потерями "
            "разрушают спрятанные данные."
        )
    if Path(out_path).exists():
        if Path(out_path).resolve() == Path(image_path).resolve():
            raise ImageError("Нельзя перезаписать исходное изображение.")
        if not force:
            raise ImageError(f"Файл {out_path} уже существует. Добавьте --force.")
    if not message:
        raise ValueError("message must not be empty")

    public_key = load_public_key(public_key_path)
    source = stego.open_image(image_path)
    payload = crypto.encrypt(message, public_key)
    stego.save_png(stego.embed(source, payload), out_path, source)
    return len(payload)


def reveal(
    image_path: str | os.PathLike,
    private_key_path: str | os.PathLike,
    passphrase: bytes | None = None,
) -> bytes:
    """Достать сообщение из изображения и расшифровать его."""
    private_key = load_private_key(private_key_path, passphrase)
    payload = stego.extract(stego.open_image(image_path))
    return crypto.decrypt(payload, private_key)


def max_message_size(image_path: str | os.PathLike, public_key_path: str | os.PathLike) -> int:
    """Максимальный размер сообщения для пары «изображение + ключ получателя»."""
    key = load_public_key(public_key_path)
    img = stego.open_image(image_path)
    return max(0, stego.capacity(img.size) - crypto.overhead(key.key_size))
