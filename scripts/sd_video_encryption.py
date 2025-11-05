"""Video encryption hooks for Stable Diffusion WebUI Forge Neo."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import gradio as gr

try:
    from modules import script_callbacks  # type: ignore
except Exception:  # noqa: BLE001
    script_callbacks = None  # type: ignore

try:
    from modules.video_encrypt import (  # type: ignore
        CRYPTOGRAPHY_IMPORT_ERROR,
        HAS_CRYPTOGRAPHY,
        VideoEncryptionError,
        encrypt_video,
    )
except ModuleNotFoundError:  # pragma: no cover - fallback when running outside WebUI
    import importlib.util

    MODULE_PATH = Path(__file__).resolve().parents[1] / "modules" / "video_encrypt.py"
    spec = importlib.util.spec_from_file_location("modules.video_encrypt", MODULE_PATH)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules["modules.video_encrypt"] = module
        spec.loader.exec_module(module)
        from modules.video_encrypt import (  # type: ignore
            CRYPTOGRAPHY_IMPORT_ERROR,
            HAS_CRYPTOGRAPHY,
            VideoEncryptionError,
            encrypt_video,
        )
    else:  # pragma: no cover - should not happen
        raise


LOGGER = logging.getLogger(__name__)
CONFIG_DIR = Path(__file__).resolve().parent / "sd-image-encryption"
CONFIG_PATH = CONFIG_DIR / "config.json"
_DEFAULT_CONFIG = {
    "enable_video_encryption": False,
    "output_suffix": ".enc",
    "keep_plain_copy": False,
}
_SUPPORTED_SUFFIX_EXTS = {".mp4", ".webm"}

_passphrase: str = ""
_config: Dict[str, Any] = {}
_hooks_installed = False
_crypto_available = bool(locals().get("HAS_CRYPTOGRAPHY", False))
_crypto_error = locals().get("CRYPTOGRAPHY_IMPORT_ERROR")

if not _crypto_available:
    LOGGER.warning(
        "Cryptography package not available; video encryption features are disabled%s",
        f": {_crypto_error}" if _crypto_error else "",
    )


def _load_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            with CONFIG_PATH.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                config = {**_DEFAULT_CONFIG, **(data or {})}
                if not _crypto_available:
                    config["enable_video_encryption"] = False
                return config
        except json.JSONDecodeError as exc:
            LOGGER.error("Failed to load video encryption config: %s", exc)
    config = dict(_DEFAULT_CONFIG)
    if not _crypto_available:
        config["enable_video_encryption"] = False
    return config


def _save_config(config: Dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in config.items() if k != "passphrase"}
    with CONFIG_PATH.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)


def _set_passphrase(value: str) -> None:
    global _passphrase
    _passphrase = value or ""
    if _passphrase:
        LOGGER.info("Video encryption passphrase updated (length: %s)", len(_passphrase))
    else:
        LOGGER.info("Video encryption passphrase cleared")


def _sanitize_suffix(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ".enc"
    if not value.startswith("."):
        value = f".{value}"
    return value


def _should_encrypt_path(path: Optional[Path]) -> bool:
    if not _crypto_available:
        return False
    if path is None:
        return False
    if path.suffix.lower() not in _SUPPORTED_SUFFIX_EXTS:
        return False
    if str(path).endswith(str(_config.get("output_suffix", ".enc"))):
        return False
    if not _config.get("enable_video_encryption"):
        return False
    if not _passphrase:
        return False
    return True


def _encrypted_path(path: Path) -> Path:
    suffix = _sanitize_suffix(_config.get("output_suffix", ".enc"))
    return Path(str(path) + suffix)


def _post_process_path(path: Optional[Path]) -> None:
    if not _should_encrypt_path(path):
        return
    plain_path = path
    encrypted_path = _encrypted_path(plain_path)

    try:
        encrypt_video(plain_path, encrypted_path, _passphrase)
    except VideoEncryptionError as exc:
        LOGGER.error("Video encryption failed for %s: %s", plain_path, exc)
        if not _config.get("keep_plain_copy", False):
            LOGGER.warning("Plain video retained at %s due to encryption failure.", plain_path)
        return
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Unexpected error while encrypting %s: %s", plain_path, exc)
        return

    if not _config.get("keep_plain_copy", False):
        try:
            plain_path.unlink(missing_ok=True)
        except OSError as exc:  # noqa: BLE001
            LOGGER.warning("Failed to remove plain video %s: %s", plain_path, exc)
    LOGGER.info("Encrypted video available at %s", encrypted_path)


class _EncryptedWriter:
    """Proxy wrapper that encrypts the produced video once closed."""

    def __init__(self, inner: Any, target_path: Path) -> None:
        self._inner = inner
        self._target_path = target_path
        self._finalized = False

    def __getattr__(self, item: str) -> Any:
        return getattr(self._inner, item)

    def __enter__(self) -> "_EncryptedWriter":
        self._inner.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> Optional[bool]:
        result = self._inner.__exit__(exc_type, exc, tb)
        self.close()
        return result

    def close(self) -> None:
        if self._finalized:
            return
        self._finalized = True
        try:
            self._inner.close()
        finally:
            try:
                _post_process_path(self._target_path)
            except Exception as exc:  # noqa: BLE001
                LOGGER.error("Unhandled error during video encryption: %s", exc)


def _to_path(uri: Any) -> Optional[Path]:
    if isinstance(uri, Path):
        return uri
    if isinstance(uri, str) and uri and not uri.startswith("http"):
        try:
            return Path(uri)
        except OSError:  # noqa: BLE001
            return None
    return None


def _wrap_writer(original):
    if getattr(original, "_sdie_wrapped", False):
        return original

    def wrapper(uri, *args, **kwargs):
        writer = original(uri, *args, **kwargs)
        path = _to_path(uri)
        if not _should_encrypt_path(path):
            return writer
        if isinstance(writer, _EncryptedWriter):
            return writer
        return _EncryptedWriter(writer, path)

    wrapper._sdie_wrapped = True  # type: ignore[attr-defined]
    return wrapper


def _wrap_writer_functions(module) -> None:
    for attr in ("get_writer", "mimwrite", "mimsave", "imwrite"):
        if hasattr(module, attr):
            original = getattr(module, attr)
            if attr == "get_writer":
                wrapped = _wrap_writer(original)
            else:
                if getattr(original, "_sdie_wrapped", False):
                    continue

                def make_wrapper(func):
                    def writer_wrapper(uri, *args, **kwargs):
                        result = func(uri, *args, **kwargs)
                        _post_process_path(_to_path(uri))
                        return result

                    writer_wrapper._sdie_wrapped = True  # type: ignore[attr-defined]
                    return writer_wrapper

                wrapped = make_wrapper(original)
            setattr(module, attr, wrapped)


def install_hooks() -> None:
    global _hooks_installed
    if _hooks_installed:
        return

    if not _crypto_available:
        LOGGER.debug("Skipping video encryption hooks because cryptography is unavailable")
        return

    try:
        import imageio  # type: ignore
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("ImageIO is not available; video encryption hooks disabled: %s", exc)
        return

    _wrap_writer_functions(imageio)
    for attr in ("v2", "v3"):
        submodule = getattr(imageio, attr, None)
        if submodule is not None:
            _wrap_writer_functions(submodule)

    _hooks_installed = True
    LOGGER.info("Video encryption hooks installed")


def _apply_settings(enable, passphrase, suffix, keep_plain):
    global _config
    _config = dict(_config)
    if _crypto_available:
        _config["enable_video_encryption"] = bool(enable)
    else:
        _config["enable_video_encryption"] = False
    _config["output_suffix"] = _sanitize_suffix(suffix)
    _config["keep_plain_copy"] = bool(keep_plain)
    _save_config(_config)
    _set_passphrase(passphrase)

    if not _crypto_available:
        status = "Video encryption unavailable: install the 'cryptography' package to enable it."
    else:
        status = (
            "Video encryption enabled."
            if _config["enable_video_encryption"]
            else "Video encryption disabled."
        )
    if _config["enable_video_encryption"] and not _passphrase:
        status += " Passphrase is empty; videos will remain unencrypted."
    return status, _config["output_suffix"], passphrase


def on_ui_tabs():
    with gr.Blocks() as block:
        gr.Markdown("## SD Image Encryption — Video")
        if not _crypto_available:
            gr.Markdown(
                "⚠️ <b>cryptography</b> no está instalado en este entorno; el cifrado de video "
                "quedará deshabilitado hasta que agregues la dependencia."
            )
        with gr.Row():
            enable = gr.Checkbox(
                label="Enable video encryption",
                value=_config.get("enable_video_encryption", False),
                interactive=_crypto_available,
            )
            keep_plain = gr.Checkbox(
                label="Keep plain video copy",
                value=_config.get("keep_plain_copy", False),
                interactive=_crypto_available,
            )
        passphrase = gr.Textbox(
            label="Passphrase",
            type="password",
            placeholder="Enter session passphrase",
            value="",
            interactive=_crypto_available,
        )
        suffix = gr.Textbox(
            label="Encrypted output suffix",
            value=_config.get("output_suffix", ".enc"),
            interactive=_crypto_available,
        )
        status = gr.Markdown("", elem_id="sdie-video-status")
        apply_btn = gr.Button("Apply settings", interactive=_crypto_available)

        apply_btn.click(
            fn=_apply_settings,
            inputs=[enable, passphrase, suffix, keep_plain],
            outputs=[status, suffix, passphrase],
        )

    return [(block, "SD Encryption", "sd_image_video_encryption")]


def _on_app_started(*_args, **_kwargs):
    install_hooks()


def _on_before_ui():
    global _config
    if not _config:
        _config = _load_config()
    install_hooks()


if not _config:
    _config = _load_config()

if script_callbacks is not None:
    if hasattr(script_callbacks, "on_before_ui"):
        script_callbacks.on_before_ui(_on_before_ui)
    if hasattr(script_callbacks, "on_ui_tabs"):
        script_callbacks.on_ui_tabs(on_ui_tabs)
    if hasattr(script_callbacks, "on_app_started"):
        script_callbacks.on_app_started(_on_app_started)
