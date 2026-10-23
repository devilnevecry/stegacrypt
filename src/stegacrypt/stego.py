"""LSB-стеганография: данные прячутся в младших битах каналов R, G и B.

Схема размещения:

* первые 32 бита (старшим вперёд) — длина полезной нагрузки в байтах;
* биты нагрузки равномерно разносятся по всему изображению с постоянным
  шагом, чтобы изменения не копились в верхних строках;
* альфа-канал не трогается.

Каждый канал меняется максимум на 1/255, на глаз это незаметно. Но это
не защита от статистического анализа: конфиденциальность даёт шифрование,
а не стеганография.
"""

from __future__ import annotations

import os
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from .errors import CapacityError, ImageError, NoMessageError

HEADER_BITS = 32
CHANNELS = 3


def capacity(size: tuple[int, int]) -> int:
    """Сколько байт нагрузки поместится в изображение размера ``size``."""
    width, height = size
    return max(0, (width * height * CHANNELS - HEADER_BITS) // 8)


def open_image(path: str | os.PathLike) -> Image.Image:
    """Открыть изображение и загрузить его в память."""
    try:
        img = Image.open(path)
        img.load()
    except FileNotFoundError:
        raise ImageError(f"Изображение не найдено: {path}") from None
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as exc:
        raise ImageError(f"Не удалось открыть изображение {path}: {exc}") from exc
    return img


def _split(img: Image.Image) -> tuple[Image.Image, Image.Image | None]:
    """Вернуть RGB-копию и альфа-канал (или None)."""
    has_alpha = "A" in img.getbands() or "transparency" in img.info
    if has_alpha:
        rgba = img.convert("RGBA")
        return rgba.convert("RGB"), rgba.getchannel("A")
    return img.convert("RGB"), None


def _positions(total: int, n_bits: int) -> range:
    step = (total - HEADER_BITS) // n_bits
    return range(HEADER_BITS, HEADER_BITS + step * n_bits, step)


def embed(img: Image.Image, payload: bytes) -> Image.Image:
    """Вернуть копию ``img`` с ``payload``, спрятанным в младших битах."""
    if not payload:
        raise ValueError("payload must not be empty")
    rgb, alpha = _split(img)
    limit = capacity(rgb.size)
    if len(payload) > limit:
        raise CapacityError(
            f"Данные ({len(payload)} байт) не помещаются в изображение "
            f"(максимум {limit} байт). Возьмите картинку побольше "
            "или сообщение покороче."
        )

    buf = bytearray(rgb.tobytes())
    n_bits = len(payload) * 8
    header = len(payload).to_bytes(4, "big")

    for i in range(HEADER_BITS):
        bit = (header[i >> 3] >> (7 - (i & 7))) & 1
        buf[i] = (buf[i] & 0xFE) | bit
    for i, pos in enumerate(_positions(len(buf), n_bits)):
        bit = (payload[i >> 3] >> (7 - (i & 7))) & 1
        buf[pos] = (buf[pos] & 0xFE) | bit

    result = Image.frombytes("RGB", rgb.size, bytes(buf))
    if alpha is not None:
        result.putalpha(alpha)
    return result


def extract(img: Image.Image) -> bytes:
    """Достать нагрузку, спрятанную :func:`embed`."""
    rgb, _ = _split(img)
    buf = rgb.tobytes()
    if len(buf) < HEADER_BITS:
        raise NoMessageError("Изображение слишком маленькое для сообщения.")

    length = 0
    for i in range(HEADER_BITS):
        length = (length << 1) | (buf[i] & 1)
    if length == 0 or length > capacity(rgb.size):
        raise NoMessageError("В изображении нет сообщения stegacrypt.")

    out = bytearray(length)
    for i, pos in enumerate(_positions(len(buf), length * 8)):
        if buf[pos] & 1:
            out[i >> 3] |= 0x80 >> (i & 7)
    return bytes(out)


def save_png(img: Image.Image, path: str | os.PathLike, source: Image.Image | None = None) -> None:
    """Сохранить результат строго как PNG (без потерь), сохранив ICC-профиль."""
    kwargs = {}
    if source is not None and source.info.get("icc_profile"):
        kwargs["icc_profile"] = source.info["icc_profile"]
    try:
        img.save(Path(path), format="PNG", **kwargs)
    except OSError as exc:
        raise ImageError(f"Не удалось сохранить {path}: {exc}") from exc
