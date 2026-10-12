#!/usr/bin/env python3
"""Build portable GUI and CLI executables with PyInstaller."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def build(name: str, source: str, windowed: bool) -> None:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        name,
        "--distpath",
        str(ROOT / "dist"),
        "--workpath",
        str(ROOT / "build" / name),
        "--specpath",
        str(ROOT / "build"),
        "--paths",
        str(ROOT),
        "--add-data",
        f"{ROOT / 'assets'}{os.pathsep}assets",
        "--icon",
        str(ROOT / "assets" / "exabeam-icon.ico"),
        "--noconfirm",
        "--clean",
    ]
    # Non-Windows credential encryption uses dynamically imported cryptography
    # modules, so explicitly collect them for PyInstaller on those platforms.
    if sys.platform != "win32":
        command.extend(["--collect-all", "cryptography"])
    command.append("--windowed" if windowed else "--console")
    command.append(str(ROOT / source))
    print("Running:", " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui-only", action="store_true")
    parser.add_argument("--cli-only", action="store_true")
    args = parser.parse_args()
    if not args.cli_only:
        build("ExabeamReplay", "exabeam-replay.py", windowed=True)
    if not args.gui_only:
        build("exabeam-replay-cli", "cli.py", windowed=False)
    print(f"Build complete. Output directory: {ROOT / 'dist'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
