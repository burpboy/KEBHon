#!/usr/bin/env python3
"""
nuitka_packager.py - Automated Binary Compilation & Stripping Tool
Author: Advanced Python Systems Automation
Description: Automated compilation wrapper for Nuitka and PyInstaller with robust error handling.
"""

import argparse
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import typing as t

# Konfigurasi Logging Tingkat Tinggi
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("Packager")


@dataclass
class BuildConfig:
    script_path: Path
    compiler: str  # "nuitka" atau "pyinstaller"
    output_dir: Path
    onefile: bool
    standalone: bool
    remove_build_dir: bool


class CompilationError(Exception):
    """Custom exception untuk kegagalan proses kompilasi."""

    pass


class DependencyError(Exception):
    """Custom exception untuk dependensi kompiler yang hilang."""

    pass


class BinaryPackager:

    def __init__(self, config: BuildConfig) -> None:
        self.config = config
        self._validate_environment()

    def _validate_environment(self) -> None:
        """Memastikan skrip target ada dan kompiler terinstal di sistem."""
        if not self.config.script_path.is_file():
            raise FileNotFoundError(
                f"Skrip target tidak ditemukan: {self.config.script_path}"
            )

        compiler_cmd = self.config.compiler.lower()
        if compiler_cmd not in ["nuitka", "pyinstaller"]:
            raise ValueError(
                f"Kompiler tidak dikenal: '{compiler_cmd}'. Gunakan 'nuitka' atau 'pyinstaller'."
            )

        if not shutil.which(compiler_cmd):
            raise DependencyError(
                f"Kompiler '{compiler_cmd}' tidak ditemukan di PATH sistem. Install terlebih dahulu."
            )

    def build(self) -> Path:
        """Mengeksekusi proses kompilasi berdasarkan kompiler yang dipilih."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            f"Memulai kompilasi '{self.config.script_path.name}' menggunakan {self.config.compiler.upper()}..."
        )

        try:
            if self.config.compiler.lower() == "nuitka":
                output_bin = self._compile_with_nuitka()
            else:
                output_bin = self._compile_with_pyinstaller()

            logger.info(f"Kompilasi sukses! Biner tersimpan di: {output_bin}")
            return output_bin

        except subprocess.CalledProcessError as e:
            logger.error(f"Proses kompiler gagal dengan exit code {e.returncode}")
            raise CompilationError(
                f"Gagal mengkompilasi {self.config.script_path.name}"
            ) from e
        finally:
            if self.config.remove_build_dir:
                self._cleanup_artifacts()

    def _compile_with_nuitka(self) -> Path:
        """Menjalankan Nuitka dengan opsi optimasi tinggi."""
        cmd = [
            sys.executable,
            "-m",
            "nuitka",
            "--follow-imports",
            "--assume-yes-for-downloads",
            f"--output-dir={self.config.output_dir.resolve()}",
        ]

        if self.config.standalone or self.config.onefile:
            cmd.append("--standalone")

        if self.config.onefile:
            cmd.append("--onefile")

        # Optimasi performa tingkat lanjut
        cmd.extend(
            [
                "--remove-output",
                "--lto=yes",
            ]
        )

        cmd.append(str(self.config.script_path.resolve()))

        logger.debug(f"Executing command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

        # Tentukan path biner hasil output Nuitka
        stem = self.config.script_path.stem
        if self.config.onefile:
            ext = ".exe" if os.name == "nt" else ".bin"
            # Nuitka onefile menghasilkan file .bin atau .exe langsung di output_dir atau .dist
            return self.config.output_dir / f"{stem}.{ext.lstrip('.')}"
        else:
            dist_dir = self.config.output_dir / f"{stem}.dist"
            return dist_dir

    def _compile_with_pyinstaller(self) -> Path:
        """Menjalankan PyInstaller dengan konfigurasi bersih."""
        cmd = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            f"--distpath={self.config.output_dir.resolve()}",
            f"--workpath={self.config.output_dir.resolve()}/build",
        ]

        if self.config.onefile:
            cmd.append("--onefile")
        else:
            cmd.append("--onedir")

        cmd.append(str(self.config.script_path.resolve()))

        logger.debug(f"Executing command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

        stem = self.config.script_path.stem
        ext = ".exe" if os.name == "nt" else ""
        return self.config.output_dir / f"{stem}{ext}"

    def _cleanup_artifacts(self) -> None:
        """Membersihkan direktori build sementara yang ditinggalkan oleh kompiler."""
        logger.info("Membersihkan direktori build sementara...")
        build_dir = self.config.output_dir / "build"
        if build_dir.exists() and build_dir.is_dir():
            shutil.rmtree(build_dir, ignore_errors=True)

        # Bersihkan file .build Nuitka jika ada
        stem = self.config.script_path.stem
        nuitka_build_dir = self.config.output_dir / f"{stem}.build"
        if nuitka_build_dir.exists() and nuitka_build_dir.is_dir():
            shutil.rmtree(nuitka_build_dir, ignore_errors=True)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automated Binary Compilation & Stripping Tool (Nuitka / PyInstaller)"
    )
    parser.add_argument(
        "script", type=Path, help="Path ke file skrip Python utama (.py)"
    )
    parser.add_argument(
        "-c",
        "--compiler",
        choices=["nuitka", "pyinstaller"],
        default="nuitka",
        help="Pilihan kompiler (default: nuitka)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("./dist"),
        help="Direktori output biner (default: ./dist)",
    )
    parser.add_argument(
        "--onefile",
        action="store_true",
        help="Bundel menjadi satu file executable tunggal",
    )
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Buat mode standalone (khusus Nuitka)",
    )
    parser.add_argument(
        "--keep-build",
        action="store_true",
        help="Jangan hapus file build sementara setelah selesai",
    )
    return parser.parse_args()


def main() -> None:
    try:
        args = parse_arguments()

        config = BuildConfig(
            script_path=args.script.resolve(),
            compiler=args.compiler,
            output_dir=args.output.resolve(),
            onefile=args.onefile,
            standalone=args.standalone,
            remove_build_dir=not args.keep_build,
        )

        packager = BinaryPackager(config)
        packager.build()

    except Exception as e:
        logger.critical(f"Fatal Error: {e}", exc_info=False)
        sys.exit(1)


if __name__ == "__main__":
    main()
