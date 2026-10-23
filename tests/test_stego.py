import pytest
from PIL import Image

from stegacrypt import stego
from stegacrypt.errors import CapacityError, ImageError, NoMessageError


def _noise(size, mode="RGB"):
    img = Image.new(mode, size)
    channels = len(img.getbands())
    img.putdata([tuple((i * 37 + c * 91) % 256 for c in range(channels)) for i in range(size[0] * size[1])])
    return img


def test_capacity_formula():
    assert stego.capacity((64, 64)) == (64 * 64 * 3 - 32) // 8
    assert stego.capacity((1, 1)) == 0


def test_roundtrip():
    img = _noise((50, 50))
    payload = bytes(range(256)) * 3
    assert stego.extract(stego.embed(img, payload)) == payload


def test_roundtrip_at_full_capacity():
    img = _noise((20, 20))
    payload = bytes([0xA5]) * stego.capacity(img.size)
    assert stego.extract(stego.embed(img, payload)) == payload


def test_only_lsb_changes():
    img = _noise((40, 40))
    out = stego.embed(img, b"hello world" * 10)
    diffs = [abs(a - b) for a, b in zip(img.tobytes(), out.tobytes())]
    assert max(diffs) <= 1


def test_changes_are_spread_over_image():
    img = _noise((100, 100))
    out = stego.embed(img, b"\xff" * 100)
    a, b = img.tobytes(), out.tobytes()
    changed = [i for i in range(len(a)) if a[i] != b[i]]
    assert changed
    assert max(changed) > len(a) // 2  # не всё в верхних строках


def test_too_large_payload():
    img = _noise((10, 10))
    with pytest.raises(CapacityError):
        stego.embed(img, b"x" * (stego.capacity(img.size) + 1))


def test_clean_image_has_no_message():
    with pytest.raises(NoMessageError):
        stego.extract(Image.new("RGB", (50, 50), (200, 100, 50)))


def test_alpha_is_preserved():
    img = _noise((30, 30), "RGBA")
    out = stego.embed(img, b"secret")
    assert out.mode == "RGBA"
    assert out.getchannel("A").tobytes() == img.getchannel("A").tobytes()
    assert stego.extract(out) == b"secret"


@pytest.mark.parametrize("mode", ["L", "P", "CMYK", "LA"])
def test_other_modes_are_converted(mode):
    img = _noise((30, 30), "RGB").convert(mode)
    assert stego.extract(stego.embed(img, b"secret")) == b"secret"


def test_open_image_errors(tmp_path):
    with pytest.raises(ImageError):
        stego.open_image(tmp_path / "missing.png")
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"not an image")
    with pytest.raises(ImageError):
        stego.open_image(bad)


def test_png_survives_save_and_load(tmp_path):
    img = _noise((50, 50))
    path = tmp_path / "out.png"
    stego.save_png(stego.embed(img, b"persist"), path)
    assert stego.extract(stego.open_image(path)) == b"persist"
