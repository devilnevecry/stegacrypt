import pytest

from stegacrypt import __version__
from stegacrypt.cli import main


def _hide(cover, keys, tmp_path, message="Привет!", name="out.png"):
    out = tmp_path / name
    code = main(["encrypt", "-i", str(cover), "-k", str(keys["alice"][1]), "-o", str(out), "-m", message])
    return code, out


def test_encrypt_then_decrypt(cover, keys, tmp_path, capsys):
    code, out = _hide(cover, keys, tmp_path)
    assert code == 0 and out.exists()
    capsys.readouterr()
    assert main(["decrypt", "-i", str(out), "-k", str(keys["alice"][0])]) == 0
    assert capsys.readouterr().out == "Привет!\n"


def test_decrypt_with_passphrase_from_env(cover, keys, tmp_path, capsys, monkeypatch):
    out = tmp_path / "bob.png"
    assert main(["encrypt", "-i", str(cover), "-k", str(keys["bob"][1]), "-o", str(out), "-m", "hi"]) == 0
    monkeypatch.setenv("STEGACRYPT_PASSPHRASE", "correct horse")
    capsys.readouterr()
    assert main(["decrypt", "-i", str(out), "-k", str(keys["bob"][0])]) == 0
    assert capsys.readouterr().out == "hi\n"


def test_decrypt_prompts_for_passphrase(cover, keys, tmp_path, capsys, monkeypatch):
    out = tmp_path / "bob.png"
    main(["encrypt", "-i", str(cover), "-k", str(keys["bob"][1]), "-o", str(out), "-m", "prompted"])
    monkeypatch.delenv("STEGACRYPT_PASSPHRASE", raising=False)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "correct horse")
    capsys.readouterr()
    assert main(["decrypt", "-i", str(out), "-k", str(keys["bob"][0])]) == 0
    assert capsys.readouterr().out == "prompted\n"


def test_wrong_key_gives_error(cover, keys, tmp_path, capsys, monkeypatch):
    _, out = _hide(cover, keys, tmp_path)
    monkeypatch.setenv("STEGACRYPT_PASSPHRASE", "correct horse")
    assert main(["decrypt", "-i", str(out), "-k", str(keys["bob"][0])]) == 1
    assert "Ошибка" in capsys.readouterr().err


def test_refuses_lossy_output(cover, keys, tmp_path, capsys):
    code, out = _hide(cover, keys, tmp_path, name="out.jpg")
    assert code == 1 and not out.exists()
    assert ".png" in capsys.readouterr().err


def test_refuses_overwrite_without_force(cover, keys, tmp_path):
    assert _hide(cover, keys, tmp_path)[0] == 0
    assert _hide(cover, keys, tmp_path)[0] == 1
    out = tmp_path / "out.png"
    args = ["encrypt", "-i", str(cover), "-k", str(keys["alice"][1]), "-o", str(out), "-m", "x", "--force"]
    assert main(args) == 0


def test_never_overwrites_source_image(cover, keys, capsys):
    args = ["encrypt", "-i", str(cover), "-k", str(keys["alice"][1]), "-o", str(cover), "-m", "x", "--force"]
    assert main(args) == 1
    assert "исходное" in capsys.readouterr().err


def test_message_too_large(cover, keys, tmp_path, capsys):
    code, _ = _hide(cover, keys, tmp_path, message="x" * 5000)
    assert code == 1
    assert "не помещаются" in capsys.readouterr().err


def test_message_from_file_and_binary_output(cover, keys, tmp_path, capsys):
    src = tmp_path / "msg.bin"
    src.write_bytes(bytes(range(256)))
    out = tmp_path / "out.png"
    assert main(["encrypt", "-i", str(cover), "-k", str(keys["alice"][1]), "-o", str(out), "-f", str(src)]) == 0
    assert main(["decrypt", "-i", str(out), "-k", str(keys["alice"][0])]) == 1  # не UTF-8
    dest = tmp_path / "restored.bin"
    assert main(["decrypt", "-i", str(out), "-k", str(keys["alice"][0]), "-o", str(dest)]) == 0
    assert dest.read_bytes() == bytes(range(256))


def test_capacity(cover, keys, capsys):
    assert main(["capacity", str(cover), "-k", str(keys["alice"][1])]) == 0
    text = capsys.readouterr().out
    assert "64x64" in text and "1532" in text and "1242" in text


def test_keygen_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("STEGACRYPT_PASSPHRASE", "pw")
    assert main(["keygen", "dave", "--bits", "2048", "--out-dir", str(tmp_path)]) == 0
    assert (tmp_path / "dave_private.key").exists()
    assert main(["keygen", "dave", "--bits", "2048", "--out-dir", str(tmp_path)]) == 1
    assert "--force" in capsys.readouterr().err


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out
