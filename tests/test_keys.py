import os
import stat

import pytest

from stegacrypt.errors import KeyFileError, PassphraseRequired
from stegacrypt.keys import generate_keypair, key_paths, load_private_key, load_public_key


def test_files_created(keys):
    private, public = keys["alice"]
    assert private.name == "alice_private.key"
    assert public.name == "alice_public.key"
    assert b"BEGIN PRIVATE KEY" in private.read_bytes()
    assert b"BEGIN PUBLIC KEY" in public.read_bytes()


@pytest.mark.skipif(os.name == "nt", reason="права POSIX")
def test_private_key_is_owner_only(keys):
    mode = stat.S_IMODE(keys["alice"][0].stat().st_mode)
    assert mode == 0o600


def test_no_overwrite_without_force(tmp_path):
    generate_keypair("carol", tmp_path, bits=2048)
    with pytest.raises(KeyFileError, match="--force"):
        generate_keypair("carol", tmp_path, bits=2048)
    generate_keypair("carol", tmp_path, bits=2048, force=True)


@pytest.mark.parametrize("name", ["../evil", "a/b", "", ".hidden", "имя", "a b"])
def test_bad_names_rejected(name):
    with pytest.raises(KeyFileError):
        key_paths(name)


def test_weak_key_rejected(tmp_path):
    with pytest.raises(KeyFileError):
        generate_keypair("weak", tmp_path, bits=1024)


def test_encrypted_private_key(keys):
    private = keys["bob"][0]
    assert b"ENCRYPTED" in private.read_bytes()
    with pytest.raises(PassphraseRequired):
        load_private_key(private)
    with pytest.raises(KeyFileError, match="Неверный пароль"):
        load_private_key(private, b"wrong")
    assert load_private_key(private, b"correct horse").key_size == 2048


def test_unencrypted_key_ignores_passphrase(keys):
    assert load_private_key(keys["alice"][0], b"unused").key_size == 2048


def test_wrong_file_types(keys, tmp_path):
    with pytest.raises(KeyFileError, match="открытый"):
        load_public_key(keys["alice"][0])
    with pytest.raises(KeyFileError, match="закрытый"):
        load_private_key(keys["alice"][1])
    with pytest.raises(KeyFileError, match="не найден"):
        load_public_key(tmp_path / "nope.key")
