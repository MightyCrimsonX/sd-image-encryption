from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

try:
    import imageio.v2 as imageio  # type: ignore
except Exception:  # pragma: no cover - skip when imageio missing
    imageio = None  # type: ignore

pytest.importorskip("cryptography")

import importlib.util

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "modules" / "video_encrypt.py"
spec = importlib.util.spec_from_file_location("modules.video_encrypt", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules["modules.video_encrypt"] = module
spec.loader.exec_module(module)

encrypt_video = module.encrypt_video
decrypt_video = module.decrypt_video
HMACValidationError = module.HMACValidationError


@pytest.fixture()
def dummy_video(tmp_path: Path) -> Path:
    if imageio is None:
        pytest.skip("imageio is not available")

    np = pytest.importorskip("numpy")

    frames = [
        (np.ones((32, 32, 3), dtype=np.uint8) * i * 50) for i in range(5)
    ]

    video_path = tmp_path / "dummy.mp4"
    try:
        imageio.mimwrite(video_path, frames, fps=5, codec="libx264")
    except Exception as exc:  # pragma: no cover - ffmpeg missing
        pytest.skip(f"ffmpeg codec unavailable: {exc}")
    return video_path


def test_encrypt_decrypt_roundtrip(dummy_video: Path, tmp_path: Path) -> None:
    encrypted_path = tmp_path / "dummy.mp4.enc"
    decrypted_path = tmp_path / "dummy_decrypted.mp4"

    encrypt_video(dummy_video, encrypted_path, "secret")

    assert dummy_video.read_bytes() != encrypted_path.read_bytes()

    decrypt_video(encrypted_path, decrypted_path, "secret")
    assert dummy_video.read_bytes() == decrypted_path.read_bytes()


def test_hmac_validation_failure(dummy_video: Path, tmp_path: Path) -> None:
    encrypted_path = tmp_path / "dummy.mp4.enc"
    encrypt_video(dummy_video, encrypted_path, "secret")

    data = bytearray(encrypted_path.read_bytes())
    data[len(data) // 2] ^= 0x01
    encrypted_path.write_bytes(data)

    with pytest.raises(HMACValidationError):
        decrypt_video(encrypted_path, tmp_path / "out.mp4", "secret")


def test_large_file_chunk_encryption(tmp_path: Path) -> None:
    size = 70 * 1024 * 1024
    plain_path = tmp_path / "large.mp4"
    with plain_path.open("wb") as handle:
        handle.write(os.urandom(size))

    encrypted_path = tmp_path / "large.mp4.enc"
    decrypted_path = tmp_path / "large_dec.mp4"

    encrypt_video(plain_path, encrypted_path, "chunk-pass")
    decrypt_video(encrypted_path, decrypted_path, "chunk-pass")

    original_hash = hashlib.sha256(plain_path.read_bytes()).hexdigest()
    decrypted_hash = hashlib.sha256(decrypted_path.read_bytes()).hexdigest()
    assert original_hash == decrypted_hash
