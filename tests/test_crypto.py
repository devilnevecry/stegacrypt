import pytest

from stegacrypt import crypto
from stegacrypt.errors import DecryptionError, NoMessageError
from stegacrypt.keys import load_private_key, load_public_key


def test_roundtrip(keys):
    pub = load_public_key(keys["alice"][1])
    priv = load_private_key(keys["alice"][0])
    payload = crypto.encrypt("Привет, мир".encode(), pub)
    assert crypto.decrypt(payload, priv) == "Привет, мир".encode()


def test_message_longer_than_rsa_limit(keys):
    """В версии 1.x сообщения длиннее ~190 байт не шифровались."""
    pub = load_public_key(keys["alice"][1])
    priv = load_private_key(keys["alice"][0])
    message = b"x" * 5000
    assert crypto.decrypt(crypto.encrypt(message, pub), priv) == message


def test_overhead_matches_payload_size(keys):
    pub = load_public_key(keys["alice"][1])
    payload = crypto.encrypt(b"hello", pub)
    assert len(payload) == crypto.overhead(pub.key_size) + len(b"hello")


def test_encryption_is_randomized(keys):
    pub = load_public_key(keys["alice"][1])
    assert crypto.encrypt(b"same", pub) != crypto.encrypt(b"same", pub)


def test_wrong_key_fails(keys):
    pub = load_public_key(keys["alice"][1])
    other = load_private_key(keys["bob"][0], b"correct horse")
    with pytest.raises(DecryptionError):
        crypto.decrypt(crypto.encrypt(b"secret", pub), other)


def test_tampering_is_detected(keys):
    pub = load_public_key(keys["alice"][1])
    priv = load_private_key(keys["alice"][0])
    payload = bytearray(crypto.encrypt(b"secret", pub))
    for index in (len(payload) - 1, 10, 4):  # тег/шифртекст, обёрнутый ключ, длина ключа
        broken = bytearray(payload)
        broken[index] ^= 0x01
        with pytest.raises(DecryptionError):
            crypto.decrypt(bytes(broken), priv)


def test_truncated_payload(keys):
    pub = load_public_key(keys["alice"][1])
    priv = load_private_key(keys["alice"][0])
    payload = crypto.encrypt(b"secret", pub)
    with pytest.raises(DecryptionError):
        crypto.decrypt(payload[:-20], priv)


def test_foreign_data_is_not_a_message(keys):
    priv = load_private_key(keys["alice"][0])
    with pytest.raises(NoMessageError):
        crypto.decrypt(b"definitely not ours" * 20, priv)
