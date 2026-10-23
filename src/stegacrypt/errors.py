"""Исключения stegacrypt."""

from __future__ import annotations


class StegacryptError(Exception):
    """Базовая ошибка; её текст безопасно показывать пользователю."""


class KeyFileError(StegacryptError):
    """Ключ не найден, повреждён, слишком слаб или не подходит."""


class PassphraseRequired(KeyFileError):
    """Закрытый ключ защищён паролем, а пароль не передан."""


class ImageError(StegacryptError):
    """Изображение не удалось открыть или сохранить."""


class CapacityError(StegacryptError):
    """Сообщение не помещается в изображение."""


class NoMessageError(StegacryptError):
    """В изображении нет сообщения stegacrypt."""


class DecryptionError(StegacryptError):
    """Сообщение найдено, но расшифровать его не удалось."""
