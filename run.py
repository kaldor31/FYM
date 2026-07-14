#!/usr/bin/env python3
"""Cross-platform launcher: creates venv, installs deps and runs main.py.

Tries to use a Python 3.9+ interpreter. If the current interpreter is too old,
it will look for an existing newer interpreter and, on macOS/Linux, attempt to
install one via Homebrew or pyenv. If that is not possible, it exits with a
clear message.
"""

import os
import platform
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from typing import Optional

PROJECT_DIR = Path(__file__).resolve().parent
VENV_DIR = PROJECT_DIR / ".venv"
REQUIREMENTS = PROJECT_DIR / "requirements.txt"

BIN_DIR = "Scripts" if platform.system() == "Windows" else "bin"
PYTHON = VENV_DIR / BIN_DIR / ("python.exe" if platform.system() == "Windows" else "python")

MIN_PYTHON = (3, 9)


def get_python_version(python_path: Path) -> tuple:
    """Return (major, minor, micro) for the given interpreter, or (0,0,0)."""
    try:
        result = subprocess.run(
            [str(python_path), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return (0, 0, 0)
    if result.returncode != 0:
        return (0, 0, 0)
    text = result.stdout.strip() or result.stderr.strip()
    # Output looks like "Python 3.11.4"
    parts = text.split()
    if len(parts) >= 2:
        try:
            ver = [int(x) for x in parts[1].split(".")[:3]]
            return tuple(ver + [0] * (3 - len(ver)))
        except ValueError:
            pass
    return (0, 0, 0)


def find_existing_python() -> Optional[Path]:
    """Search PATH for a Python 3.9+ interpreter."""
    candidates = []
    for major in range(13, 8, -1):
        for minor in range(9, -1, -1):
            if major == 3 and minor < 9:
                continue
            if major == 3:
                candidates.extend([f"python3.{minor}", f"python{major}.{minor}"])
            else:
                candidates.append(f"python{major}.{minor}")
    # Also check generic python3 / python
    candidates.extend(["python3", "python"])

    seen = set()
    for cmd in candidates:
        path_str = shutil.which(cmd)
        if not path_str:
            continue
        path = Path(path_str).resolve()
        if path in seen:
            continue
        seen.add(path)
        if get_python_version(path) >= MIN_PYTHON:
            return path
    return None


def try_install_python() -> Optional[Path]:
    """Best-effort attempt to install Python 3.11 if no suitable interpreter exists."""
    system = platform.system()

    if system == "Darwin" and shutil.which("brew"):
        print("[run] Python 3.9+ not found; attempting to install Python 3.11 via Homebrew...")
        try:
            subprocess.run(["brew", "install", "python@3.11"], check=True)
        except subprocess.CalledProcessError:
            print("[run] Homebrew install failed.", file=sys.stderr)
            return None
        for prefix in [Path("/opt/homebrew"), Path("/usr/local")]:
            candidate = prefix / "bin" / "python3.11"
            if candidate.exists() and get_python_version(candidate) >= MIN_PYTHON:
                return candidate
        return None

    if system == "Linux" and shutil.which("pyenv"):
        print("[run] Python 3.9+ not found; attempting to install Python 3.11 via pyenv...")
        try:
            subprocess.run(["pyenv", "install", "-s", "3.11.9"], check=True)
        except subprocess.CalledProcessError:
            print("[run] pyenv install failed.", file=sys.stderr)
            return None
        # pyenv puts the shim in PATH if the shell is configured; try to find it.
        pyenv_root = os.environ.get("PYENV_ROOT", Path.home() / ".pyenv")
        candidate = Path(pyenv_root) / "versions" / "3.11.9" / "bin" / "python3.11"
        if candidate.exists() and get_python_version(candidate) >= MIN_PYTHON:
            return candidate
        return None

    return None


def find_suitable_python() -> Path:
    """Return a Python 3.9+ interpreter, installing one if necessary and possible."""
    current = Path(sys.executable).resolve()
    if get_python_version(current) >= MIN_PYTHON:
        return current

    existing = find_existing_python()
    if existing:
        print(f"[run] using existing Python {get_python_version(existing)[:2]}: {existing}")
        return existing

    installed = try_install_python()
    if installed:
        print(f"[run] installed Python {get_python_version(installed)[:2]}: {installed}")
        return installed

    print(
        f"[run] error: Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required. "
        "Please install it and try again.",
        file=sys.stderr,
    )
    sys.exit(1)


def get_venv_python() -> Optional[Path]:
    """Return the path to the venv interpreter if it exists."""
    candidate = VENV_DIR / BIN_DIR / ("python.exe" if platform.system() == "Windows" else "python")
    if candidate.exists():
        return candidate
    return None


def create_venv() -> Path:
    """Create or recreate the venv with the best available Python 3.9+ interpreter."""
    candidate = find_suitable_python()
    venv_python = get_venv_python()

    if venv_python:
        venv_version = get_python_version(venv_python)
        candidate_version = get_python_version(candidate)
        if venv_version >= MIN_PYTHON and venv_version >= candidate_version:
            return venv_python
        print("[run] existing venv has an older Python; recreating...")
        shutil.rmtree(VENV_DIR)

    print(f"[run] creating virtual environment with {candidate}...")
    VENV_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(candidate), "-m", "venv", str(VENV_DIR)], check=True)
    return get_venv_python() or (VENV_DIR / BIN_DIR / ("python.exe" if platform.system() == "Windows" else "python"))


def install_deps(python_path: Path) -> None:
    print("[run] installing dependencies...")
    subprocess.check_call([str(python_path), "-m", "pip", "install", "-r", str(REQUIREMENTS)])


def deps_satisfied(python_path: Path) -> bool:
    try:
        subprocess.check_call(
            [str(python_path), "-c", "import cryptography, prompt_toolkit, upnpclient, kademlia"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def main() -> int:
    python_path = create_venv()
    if not REQUIREMENTS.exists():
        print("[run] requirements.txt not found", file=sys.stderr)
        return 1
    if not deps_satisfied(python_path):
        install_deps(python_path)
    return subprocess.run([str(python_path), str(PROJECT_DIR / "main.py"), *sys.argv[1:]]).returncode


if __name__ == "__main__":
    sys.exit(main())
