import importlib.util
import sys
from pathlib import Path

from modules.script_callbacks import on_app_started
from sd_image_encryption import password, app


def _load_video_module() -> None:
    try:
        import sd_video_encryption  # noqa: F401  # type: ignore
        return
    except ModuleNotFoundError:
        module_path = Path(__file__).resolve().with_name("sd_video_encryption.py")
        try:
            spec = importlib.util.spec_from_file_location("sd_video_encryption", module_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules["sd_video_encryption"] = module
                spec.loader.exec_module(module)
                return
            raise ImportError(f"Unable to create module spec for {module_path}")
        except Exception as exc:  # noqa: BLE001
            print(
                "[sd-image-encryption] Failed to initialize video encryption module: "
                f"{exc}"
            )
    except Exception as exc:  # noqa: BLE001
        print(f"[sd-image-encryption] Failed to initialize video encryption module: {exc}")


_load_video_module()

RST = '\033[0m'
ORG = '\033[38;5;208m'
BLUE = '\033[38;5;39m'
RED = '\033[38;5;196m'
AR = f'{BLUE}●{RST}'
TITLE = 'Image Encryption:'

if password == '':
    print(f'{AR} {TITLE} {RED}Disabled{RST}, --encrypt-pass value is empty.')
elif not password:
    print(f'{AR} {TITLE} {RED}Disabled{RST}, Missing --encrypt-pass command line argument.')
else:
    print(f'{AR} {TITLE} {BLUE}Enabled{RST} {ORG}v7{RST}\n{AR} {TITLE} Check the release page for decrypting images locally on Windows https://github.com/gutris1/sd-image-encryption')
    on_app_started(app)
