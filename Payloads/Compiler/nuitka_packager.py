#!/usr/bin/env python3
"""
Nuitka Automated Binary Packager
---------------------------------
Membuat binary executable dari script Python menggunakan Nuitka.
Fitur:
  - Kompilasi C-extension (faster startup)
  - Stripping binary (reduksi ukuran)
  - Output terpisah per modul
  - Deteksi Python version & Nuitka availability
  - Error handling yang robust

Usage:
    python nuitka_packager.py <input_script> [options]

Options:
    --strip         : Strip binary untuk mengurangi ukuran file
    --onefile       : Buat single-file executable (jika didukung)
    --name NAME     : Nama custom untuk output binary
    --version       : Tampilkan versi Nuitka dan exit
    --help          : Tampilkan bantuan
"""

import sys
import os
import subprocess
import argparse
import shutil
import platform
from pathlib import Path


def check_python_version():
    """Memastikan Python version minimal 3.8."""
    if sys.version_info < (3, 8):
        print(f"[ERROR] Python 3.8+ diperlukan. Versi saat ini: {sys.version}")
        sys.exit(1)


def check_nuitka_installed():
    """Memeriksa apakah Nuitka terinstall."""
    try:
        import nuitka
        return True
    except ImportError:
        return False


def install_nuitka():
    """Menginstall Nuitka jika belum tersedia."""
    print("[INFO] Nuitka tidak ditemukan. Menginstall...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "nuitka"])
        print("[OK] Nuitka berhasil diinstall.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Gagal menginstall Nuitka: {e}")
        return False


def get_build_dir(script_name):
    """Membuat direktori build yang unik berdasarkan nama script."""
    base_name = Path(script_name).stem
    build_dir = Path("dist_nuitka") / f"{base_name}_build"
    build_dir.mkdir(parents=True, exist_ok=True)
    return build_dir


def strip_binary(binary_path):
    """Melakukan stripping pada binary executable."""
    if not binary_path.exists():
        print(f"[WARN] File binary tidak ditemukan: {binary_path}")
        return False

    # Pilih perintah strip berdasarkan OS
    system = platform.system()
    if system == "Darwin":
        cmd = ["strip", str(binary_path)]
    elif system == "Windows":
        # Windows biasanya sudah stripped atau menggunakan upx
        # Kita gunakan strip bawaan mingw jika ada, atau skip
        print("[INFO] Stripping pada Windows mungkin memerlukan tools tambahan (misal strip dari MinGW). Melewati.")
        return True
    else:  # Linux
        cmd = ["strip", str(binary_path)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[OK] Binary berhasil di-strip: {binary_path.name}")
            return True
        else:
            print(f"[WARN] Gagal strip: {result.stderr}")
            return False
    except FileNotFoundError:
        print(f"[WARN] Perintah 'strip' tidak ditemukan. Pastikan binutils terinstall.")
        return False


def run_nuitka(script_path, build_dir, options):
    """Menjalankan proses kompilasi Nuitka."""
    # Konstruksi argumen Nuitka
    args = [
        sys.executable, "-m", "nuitka",
        "--standalone",  # Paket semua dependensi
        "--output-dir=" + str(build_dir),
        "--assume-no-system-imports-nosearch",  # Hindari noise import
        "--nofollow-import-to=tests",  # Skip test modules
        "--nofollow-import-to=__pycache__",
        "--nofollow-import-to=.git",
    ]

    # Opsi tambahan
    if options.strip:
        args.append("--enable-plugin=python-report") # Opsional: laporan plugin
        # Catatan: Nuitka tidak punya flag --strip langsung, 
        # tapi kita bisa menggunakan --remove-output untuk membersihkan intermediate files
        # Atau kita lakukan stripping manual setelah build selesai.
    
    if options.onefile and platform.system() != "Darwin":
        # One-file support on Darwin masih experimental/limited
        args.append("--onefile")

    if options.name:
        args.extend(["--output-filename=" + options.name])

    # Tambahkan script input
    args.append(str(script_path))

    print(f"[INFO] Menjalankan Nuitka: {' '.join(args)}")
    
    try:
        result = subprocess.run(args, capture_output=True, text=True)
        
        if result.returncode != 0:
            print("[ERROR] Kompilasi gagal:")
            print(result.stderr)
            return False
        
        print("[OK] Kompilasi selesai.")
        return True

    except Exception as e:
        print(f"[ERROR] Eksekusi Nuitka gagal: {e}")
        return False


def post_process(build_dir, script_name, options):
    """Proses pasca-kompilasi: stripping, pembersihan, dan verifikasi."""
    base_name = Path(script_name).stem
    
    # Cari file executable
    system = platform.system()
    extensions = ['.exe'] if system == "Windows" else ['']
    
    found_binaries = []
    for ext in extensions:
        pattern = Path(build_dir) / f"*{base_name}*{ext}"
        found_binaries.extend(pattern.parent.glob(pattern.name))
    
    # Jika satu file (onefile), pathnya berbeda
    if options.onefile:
        onefile_path = Path(build_dir) / f"{base_name}.onefile"
        if onefile_path.exists():
            found_binaries.append(onefile_path)
        else:
            # Coba cari ekstensi lain
            for ext in ['', '.exe', '.dmg']:
                p = Path(build_dir) / f"{base_name}{ext}"
                if p.exists():
                    found_binaries.append(p)

    if not found_binaries:
        print("[WARN] Tidak dapat menemukan binary hasil kompilasi di:", build_dir)
        print("[INFO] Isi direktori build:")
        for item in build_dir.iterdir():
            print(f"   - {item.name}")
        return None

    # Ambil binary pertama yang ditemukan
    target_binary = found_binaries[0]
    
    # Lakukan stripping jika diminta
    if options.strip:
        strip_binary(target_binary)

    # Bersihkan folder build intermediate jika bukan onefile
    # Untuk onefile, folder build besar diperlukan untuk runtime
    if not options.onefile:
        print(f"[INFO] Membersihkan folder intermediate di {build_dir}")
        # Kita biarkan karena Nuitka butuh folder tersebut untuk standalone mode
        # Tapi kita bisa hapus .c source code jika mau hemat tempat
        for item in build_dir.rglob("*.c"):
            item.unlink()
            
    return target_binary


def main():
    parser = argparse.ArgumentParser(description="Nuitka Automated Binary Packager")
    parser.add_argument("script", help="Path ke script Python utama (.py)")
    parser.add_argument("--strip", action="store_true", help="Strip binary executable")
    parser.add_argument("--onefile", action="store_true", help="Buat single-file executable")
    parser.add_argument("--name", type=str, default=None, help="Nama output binary")
    parser.add_argument("--force-install", action="store_true", help="Paksa install ulang Nuitka")
    
    args = parser.parse_args()

    # Validasi input
    if not os.path.isfile(args.script):
        print(f"[ERROR] File '{args.script}' tidak ditemukan.")
        sys.exit(1)

    # Cek Python Version
    check_python_version()

    # Cek & Install Nuitka
    if not check_nuitka_installed() or args.force_install:
        if not install_nuitka():
            sys.exit(1)

    # Setup Direktori Build
    build_dir = get_build_dir(args.script)
    print(f"[INFO] Direktori build: {build_dir}")

    # Jalankan Kompilasi
    success = run_nuitka(args.script, build_dir, args)
    
    if not success:
        sys.exit(1)

    # Post-processing
    result_binary = post_process(build_dir, args.script, args)

    if result_binary:
        print(f"\n[SUCCESS] Binary siap digunakan:")
        print(f"   Lokasi: {result_binary.absolute()}")
        size_mb = result_binary.stat().st_size / (1024 * 1024)
        print(f"   Ukuran: {size_mb:.2f} MB")
    else:
        print("\n[WARN] Proses selesai, namun binary tidak terverifikasi.")
        print(f"Periksa direktori: {build_dir}")

if __name__ == "__main__":
    main()
