"""Utilities for encrypting and decrypting video files in streaming mode."""
from __future__ import annotations

import base64
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Tuple

try:  # pragma: no cover - exercised indirectly via HAS_CRYPTOGRAPHY
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAS_CRYPTOGRAPHY = True
    CRYPTOGRAPHY_IMPORT_ERROR: ModuleNotFoundError | None = None
except ModuleNotFoundError as exc:  # pragma: no cover - environment without dependency
    HAS_CRYPTOGRAPHY = False
    CRYPTOGRAPHY_IMPORT_ERROR = exc

    class InvalidSignature(Exception):  # type: ignore[override]
        """Fallback placeholder when cryptography is unavailable."""



__all__ = [
    "VideoEncryptionError",
    "VideoDecryptionError",
    "HMACValidationError",
    "encrypt_video",
    "decrypt_video",
    "HAS_CRYPTOGRAPHY",
    "CRYPTOGRAPHY_IMPORT_ERROR",
]


_LOGGER = logging.getLogger(__name__)

_MAGIC = "SDE1"
_VERSION = "1"
_HEADER_TERMINATOR = b"\n\n"
_DEFAULT_INFO = b"sd-image-video-encryption"
_HMAC_PLACEHOLDER = base64.b64encode(b"\x00" * 32).decode("ascii")
_SUPPORTED_ALGORITHMS = {"AES-CTR"}


class VideoEncryptionError(Exception):
    """Base exception for video encryption errors."""


class VideoDecryptionError(VideoEncryptionError):
    """Raised when a video cannot be decrypted."""


class HMACValidationError(VideoDecryptionError):
    """Raised when the ciphertext integrity check fails."""


@dataclass
class _DerivedKeys:
    encryption: bytes
    hmac: bytes


def _require_crypto() -> None:
    if not HAS_CRYPTOGRAPHY:
        message = (
            "Video encryption requires the 'cryptography' package. "
            "Install it via 'pip install cryptography' to enable this feature."
        )
        raise VideoEncryptionError(message) from CRYPTOGRAPHY_IMPORT_ERROR


def _derive_keys(passphrase: str, salt: bytes, *, length: int = 32) -> _DerivedKeys:
    """Derive encryption and HMAC keys from a passphrase and salt."""
    if not passphrase:
        raise VideoEncryptionError("Passphrase is required for key derivation.")

    _require_crypto()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length * 2,
        salt=salt,
        info=_DEFAULT_INFO,
    )
    key_material = hkdf.derive(passphrase.encode("utf-8"))
    return _DerivedKeys(encryption=key_material[:length], hmac=key_material[length:])


def _build_header(alg: str, salt: bytes, nonce: bytes, hmac_b64: str) -> bytes:
    header_lines = [
        _MAGIC,
        _VERSION,
        alg,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(nonce).decode("ascii"),
        hmac_b64,
    ]
    header_text = "\n".join(header_lines) + "\n\n"
    return header_text.encode("utf-8")


def _read_header(handle: BinaryIO) -> Tuple[str, bytes, bytes, str]:
    buffer = bytearray()
    while True:
        chunk = handle.read(1)
        if not chunk:
            raise VideoDecryptionError("Unexpected end of file while reading header.")
        buffer.extend(chunk)
        if buffer.endswith(_HEADER_TERMINATOR):
            break
        if len(buffer) > 8192:
            raise VideoDecryptionError("Header is too large or malformed.")

    header_text = buffer[:- len(_HEADER_TERMINATOR)].decode("utf-8")
    parts = header_text.split("\n")
    if len(parts) != 6:
        raise VideoDecryptionError("Invalid header format.")

    magic, version, alg, salt_b64, nonce_b64, hmac_b64 = parts
    if magic != _MAGIC:
        raise VideoDecryptionError("Unknown encrypted video format magic.")
    if version != _VERSION:
        raise VideoDecryptionError("Unsupported encrypted video version.")
    if alg not in _SUPPORTED_ALGORITHMS:
        raise VideoDecryptionError(f"Unsupported algorithm '{alg}'.")

    try:
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
    except Exception as exc:  # noqa: BLE001
        raise VideoDecryptionError("Invalid base64 encoding in header.") from exc

    return alg, salt, nonce, hmac_b64


def _ensure_chunk_size(chunk_size: int) -> int:
    if chunk_size <= 0:
        raise VideoEncryptionError("Chunk size must be a positive integer.")
    return chunk_size


def _sanitize_paths(in_path: Path, out_path: Path) -> None:
    if not in_path.exists() or not in_path.is_file():
        raise VideoEncryptionError(f"Input file '{in_path}' does not exist or is not a file.")
    out_dir = out_path.parent
    if not out_dir.exists():
        out_dir.mkdir(parents=True, exist_ok=True)


def encrypt_video(
    in_path: Path | str,
    out_path: Path | str,
    passphrase: str,
    *,
    alg: str = "AES-CTR",
    chunk_size: int = 4 * 1024 * 1024,
) -> Path:
    """Encrypt a video file in streaming mode and write the ciphertext to *out_path*.

    Parameters
    ----------
    in_path: Path | str
        Path to the plaintext video file.
    out_path: Path | str
        Path where the encrypted video will be written.
    passphrase: str
        Passphrase used to derive encryption keys.
    alg: str
        Symmetric encryption algorithm. Currently only ``AES-CTR`` is supported.
    chunk_size: int
        Size of chunks read from the input file. Defaults to 4 MiB.

    Returns
    -------
    Path
        Path to the encrypted video file.
    """
    if alg not in _SUPPORTED_ALGORITHMS:
        raise VideoEncryptionError(f"Unsupported algorithm '{alg}'.")
    chunk_size = _ensure_chunk_size(chunk_size)

    _require_crypto()

    in_path = Path(in_path)
    out_path = Path(out_path)
    _sanitize_paths(in_path, out_path)

    salt = os.urandom(16)
    nonce = os.urandom(16)
    keys = _derive_keys(passphrase, salt)

    cipher = Cipher(algorithms.AES(keys.encryption), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    mac = hmac.HMAC(keys.hmac, hashes.SHA256())

    header = _build_header(alg, salt, nonce, _HMAC_PLACEHOLDER)

    with in_path.open("rb") as src, out_path.open("w+b") as dst:
        dst.write(header)
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            encrypted = encryptor.update(chunk)
            if encrypted:
                dst.write(encrypted)
                mac.update(encrypted)
        final_chunk = encryptor.finalize()
        if final_chunk:
            dst.write(final_chunk)
            mac.update(final_chunk)

        digest = mac.finalize()
        final_header = _build_header(alg, salt, nonce, base64.b64encode(digest).decode("ascii"))
        dst.seek(0)
        dst.write(final_header)
        dst.flush()

    _LOGGER.info("Encrypted video written to %s", out_path)
    return out_path


def decrypt_video(
    in_path: Path | str,
    out_path: Path | str,
    passphrase: str,
    *,
    alg: str = "AES-CTR",
    chunk_size: int = 4 * 1024 * 1024,
) -> Path:
    """Decrypt an encrypted video produced by :func:`encrypt_video`."""
    chunk_size = _ensure_chunk_size(chunk_size)
    _require_crypto()
    in_path = Path(in_path)
    out_path = Path(out_path)
    _sanitize_paths(in_path, out_path)

    with in_path.open("rb") as src:
        alg_name, salt, nonce, expected_hmac_b64 = _read_header(src)
        if alg_name != alg:
            _LOGGER.warning("Decrypting with algorithm override '%s' (header: %s)", alg, alg_name)
        keys = _derive_keys(passphrase, salt)
        cipher = Cipher(algorithms.AES(keys.encryption), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        mac = hmac.HMAC(keys.hmac, hashes.SHA256())

        tmp_dir = out_path.parent
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=tmp_dir) as tmp_file:
            tmp_path = Path(tmp_file.name)
            try:
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    mac.update(chunk)
                    decrypted = decryptor.update(chunk)
                    if decrypted:
                        tmp_file.write(decrypted)
                final_chunk = decryptor.finalize()
                if final_chunk:
                    tmp_file.write(final_chunk)

                try:
                    mac.verify(base64.b64decode(expected_hmac_b64))
                except (InvalidSignature, ValueError) as exc:  # noqa: BLE001
                    raise HMACValidationError("Encrypted video failed integrity verification.") from exc

            except Exception:
                tmp_file.close()
                tmp_path.unlink(missing_ok=True)
                raise

        tmp_path.replace(out_path)

    _LOGGER.info("Decrypted video written to %s", out_path)
    return out_path
