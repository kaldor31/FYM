#!/usr/bin/env python3
"""Cross-platform launcher: creates venv, installs deps and runs main.py."""

import platform
import subprocess
import sys
import venv
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
VENV_DIR = PROJECT_DIR / ".venv"
REQUIREMENTS = PROJECT_DIR / "requirements.txt"

BIN_DIR = "Scripts" if platform.system() == "Windows" else "bin"
PYTHON = VENV_DIR / BIN_DIR / ("python.exe" if platform.system() == "Windows" else "python")


def create_venv() -> None:
    if VENV_DIR.exists():
        return
    print("[run] creating virtual environment...")
    VENV_DIR.mkdir(parents=True, exist_ok=True)
    venv.create(VENV_DIR, with_pip=True)


def install_deps() -> None:
    print("[run] installing dependencies...")
    subprocess.check_call([str(PYTHON), "-m", "pip", "install", "-r", str(REQUIREMENTS)])


def deps_satisfied() -> bool:
    try:
        subprocess.check_call(
            [str(PYTHON), "-c", "import cryptography, prompt_toolkit, upnpclient, kademlia"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def main() -> int:
    create_venv()
    if not REQUIREMENTS.exists():
        print("[run] requirements.txt not found", file=sys.stderr)
        return 1
    if not deps_satisfied():
        install_deps()
    return subprocess.run([str(PYTHON), str(PROJECT_DIR / "main.py"), *sys.argv[1:]]).returncode


if __name__ == "__main__":
    sys.exit(main())
