from __future__ import annotations

import pytest
from PIL import Image

from stegacrypt.keys import generate_keypair

PASSPHRASE = b"correct horse"


@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    """Две пары ключей 2048 бит: alice без пароля, bob с паролем."""
    base = tmp_path_factory.mktemp("keys")
    alice = generate_keypair("alice", base, bits=2048)
    bob = generate_keypair("bob", base, bits=2048, passphrase=PASSPHRASE)
    return {"alice": alice, "bob": bob, "dir": base}


@pytest.fixture()
def cover(tmp_path):
    """Тестовое изображение 64x64 с градиентом (ёмкость 1532 байта)."""
    img = Image.new("RGB", (64, 64))
    img.putdata([(x * 4 % 256, y * 4 % 256, (x + y) * 2 % 256) for y in range(64) for x in range(64)])
    path = tmp_path / "cover.png"
    img.save(path)
    return path
