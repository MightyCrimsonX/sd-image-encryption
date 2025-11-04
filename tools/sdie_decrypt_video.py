"""Command-line tool to decrypt videos produced by SD Image Encryption."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

try:
    from modules.video_encrypt import HMACValidationError, VideoDecryptionError, decrypt_video  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - running outside WebUI
    import importlib.util

    ROOT = Path(__file__).resolve().parents[1]
    MODULE_PATH = ROOT / "modules" / "video_encrypt.py"
    spec = importlib.util.spec_from_file_location("modules.video_encrypt", MODULE_PATH)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules["modules.video_encrypt"] = module
        spec.loader.exec_module(module)
        from modules.video_encrypt import HMACValidationError, VideoDecryptionError, decrypt_video  # type: ignore
    else:  # pragma: no cover
        raise


LOGGER = logging.getLogger("sdie.decrypt")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Decrypt WAN/Forge Neo encrypted video files.")
    parser.add_argument("--in", dest="input_path", required=True, help="Encrypted video input path.")
    parser.add_argument("--out", dest="output_path", required=True, help="Path for the decrypted video.")
    parser.add_argument("--passphrase", dest="passphrase", required=True, help="Passphrase used during encryption.")
    parser.add_argument(
        "--chunk-size",
        dest="chunk_size",
        type=int,
        default=4 * 1024 * 1024,
        help="Chunk size for streaming decryption (default: 4 MiB).",
    )
    return parser.parse_args(argv)


def configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging()

    input_path = Path(args.input_path)
    output_path = Path(args.output_path)

    try:
        decrypt_video(input_path, output_path, args.passphrase, chunk_size=args.chunk_size)
    except HMACValidationError as exc:
        LOGGER.error("Integrity check failed: %s", exc)
        return 2
    except VideoDecryptionError as exc:
        LOGGER.error("Unable to decrypt video: %s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Unexpected error while decrypting %s: %s", input_path, exc)
        return 3

    LOGGER.info("Decrypted video written to %s", output_path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
