#!/usr/bin/env python3
"""
steganography.py
================
LSB & Frequency Domain Image/Audio Payload Embedding Engine

Menyembunyikan payload (file biner) ke dalam:
  - Gambar (PNG/BMP) via LSB & DCT (Frequency Domain)
  - Audio (WAV 16-bit PCM) via LSB & DFT (Frequency Domain)

Fitur:
  - Auto-detect kapasitas
  - Header terstruktur (magic + nama file + ukuran + checksum CRC32)
  - Kompresi opsional (zlib) + enkripsi opsional (XOR stream SHA-256)
  - Verifikasi integritas (CRC32) saat ekstraksi
  - CLI lengkap

Dependensi:
  - Pillow  (pip install pillow)   -> untuk image
  - numpy   (pip install numpy)    -> untuk audio & DCT/DFT
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import wave
import zlib
from pathlib import Path
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Optional imports (graceful degradation)
# ---------------------------------------------------------------------------
try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False

try:
    from PIL import Image
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False


# ---------------------------------------------------------------------------
# Konstanta & Header
# ---------------------------------------------------------------------------
MAGIC = b"STEG"
VERSION = 1

# Header layout (little-endian):
#   magic(4) | version(1) | flags(1) | filename_len(1) | filename(var) |
#   payload_len(8) | crc32(4) | reserved(2)
_HEADER_FMT_PREFIX = "<4sBB"      # magic, version, flags
_HEADER_FMT_SUFFIX = "<QIH"       # payload_len, crc32, reserved

FLAG_COMPRESSED = 0x01
FLAG_ENCRYPTED = 0x02

DCT_BLOCK = 8
DCT_COEFF_MID = 4                 # koefisien mid-frequency untuk penyisipan


# ---------------------------------------------------------------------------
# Utilitas umum
# ---------------------------------------------------------------------------
def _require_numpy() -> None:
    if not _HAS_NUMPY:
        raise RuntimeError("numpy diperlukan. Install: pip install numpy")


def _require_pil() -> None:
    if not _HAS_PIL:
        raise RuntimeError("Pillow diperlukan. Install: pip install pillow")


def _key_bytes(key: Optional[str]) -> Optional[bytes]:
    """Normalisasi kunci CLI (str) ke bytes."""
    if key is None or key == "":
        return None
    return key.encode("utf-8")


def _xor_stream(data: bytes, key: bytes) -> bytes:
    """XOR stream cipher sederhana berbasis SHA-256 counter mode (simetris)."""
    if not key:
        return data
    out = bytearray(len(data))
    block = hashlib.sha256(key).digest()
    counter = 0
    for i in range(0, len(data), 32):
        if counter > 0:
            block = hashlib.sha256(key + counter.to_bytes(8, "little")).digest()
        chunk = data[i:i + 32]
        for j, b in enumerate(chunk):
            out[i + j] = b ^ block[j]
        counter += 1
    return bytes(out)


def _build_header(filename: str, payload_len: int, crc32: int, flags: int) -> bytes:
    fname = filename.encode("utf-8")
    if len(fname) > 255:
        raise ValueError("Nama file terlalu panjang (maks 255 byte UTF-8).")
    prefix = struct.pack(_HEADER_FMT_PREFIX, MAGIC, VERSION, flags)
    fname_field = struct.pack("<B", len(fname)) + fname
    suffix = struct.pack(_HEADER_FMT_SUFFIX, payload_len, crc32, 0)
    return prefix + fname_field + suffix


def _parse_header(data: bytes) -> Tuple[dict, int]:
    """Return (header_dict, header_size)."""
    if len(data) < 8:
        raise ValueError("Data terlalu pendek untuk header.")
    magic, version, flags = struct.unpack(_HEADER_FMT_PREFIX, data[:6])
    if magic != MAGIC:
        raise ValueError("Magic tidak cocok — payload tidak ditemukan.")
    if version != VERSION:
        raise ValueError(f"Versi header tidak didukung: {version}")
    pos = 6
    fname_len = data[pos]
    pos += 1
    if len(data) < pos + fname_len + 14:
        raise ValueError("Header terpotong.")
    filename = data[pos:pos + fname_len].decode("utf-8", errors="replace")
    pos += fname_len
    payload_len, crc32, _reserved = struct.unpack(
        _HEADER_FMT_SUFFIX, data[pos:pos + 14]
    )
    pos += 14
    return {
        "version": version,
        "flags": flags,
        "filename": filename,
        "payload_len": payload_len,
        "crc32": crc32,
    }, pos


def _prepare_payload(data: bytes, key: Optional[bytes],
                     compress: bool) -> Tuple[bytes, int]:
    """Kompresi + enkripsi payload. Return (processed, flags)."""
    flags = 0
    if compress:
        data = zlib.compress(data, 9)
        flags |= FLAG_COMPRESSED
    if key:
        data = _xor_stream(data, key)
        flags |= FLAG_ENCRYPTED
    return data, flags


def _restore_payload(data: bytes, key: Optional[bytes], flags: int) -> bytes:
    if flags & FLAG_ENCRYPTED:
        if not key:
            raise ValueError("Payload terenkripsi, kunci diperlukan.")
        data = _xor_stream(data, key)
    if flags & FLAG_COMPRESSED:
        data = zlib.decompress(data)
    return data


# ---------------------------------------------------------------------------
# BITS <-> BYTES
# ---------------------------------------------------------------------------
def _bytes_to_bits(data: bytes) -> "np.ndarray":
    _require_numpy()
    arr = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(arr)


def _bits_to_bytes(bits: "np.ndarray") -> bytes:
    _require_numpy()
    bits = bits[:(len(bits) // 8) * 8]
    return np.packbits(bits).tobytes()


def _bits_to_bytes_py(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (bits[i + j] & 1)
        out.append(byte)
    return bytes(out)


def _bytes_to_bits_py(data: bytes) -> list[int]:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


# ---------------------------------------------------------------------------
# ===== IMAGE : LSB =====
# ---------------------------------------------------------------------------
def image_lsb_embed(image_path: str, payload_path: str, output_path: str,
                    key: Optional[bytes] = None, compress: bool = True) -> dict:
    _require_pil()
    _require_numpy()

    img = Image.open(image_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    h, w, _ = arr.shape

    raw = Path(payload_path).read_bytes()
    processed, flags = _prepare_payload(raw, key, compress)
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    header = _build_header(Path(payload_path).name, len(processed), crc, flags)
    blob = header + processed
    bits = _bytes_to_bits(blob)

    capacity = arr.size
    if len(bits) > capacity:
        raise ValueError(
            f"Kapasitas tidak cukup. Butuh {len(bits)} bit, tersedia {capacity} bit. "
            f"Gunakan gambar lebih besar atau kurangi payload."
        )

    flat = arr.reshape(-1).copy()
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    arr = flat.reshape(h, w, 3)

    Image.fromarray(arr, "RGB").save(output_path, format="PNG")
    return {
        "output": output_path,
        "bits_used": int(len(bits)),
        "capacity_bits": int(capacity),
        "usage_ratio": round(len(bits) / capacity, 6),
    }


def image_lsb_extract(image_path: str, output_path: Optional[str] = None,
                      key: Optional[bytes] = None) -> dict:
    _require_pil()
    _require_numpy()

    img = Image.open(image_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    bits = (arr.reshape(-1) & 0x01).astype(np.uint8)

    # Baca header bertahap
    min_bits = 7 * 8
    if len(bits) < min_bits:
        raise ValueError("Gambar terlalu kecil untuk menyimpan header.")
    head = _bits_to_bytes(bits[:min_bits])
    magic, _v, _f = struct.unpack(_HEADER_FMT_PREFIX, head[:6])
    if magic != MAGIC:
        raise ValueError("Tidak ada payload steganografi terdeteksi.")
    fname_len = head[6]
    header_bits = (7 + fname_len + 14) * 8
    if len(bits) < header_bits:
        raise ValueError("Header payload tidak lengkap.")
    header_blob = _bits_to_bytes(bits[:header_bits])
    header, hdr_size = _parse_header(header_blob)

    total_bits = hdr_size * 8 + header["payload_len"] * 8
    if len(bits) < total_bits:
        raise ValueError("Data payload terpotong.")

    payload = _bits_to_bytes(bits[hdr_size * 8:total_bits])
    restored = _restore_payload(payload, key, header["flags"])
    if (zlib.crc32(restored) & 0xFFFFFFFF) != header["crc32"]:
        raise ValueError("CRC32 mismatch — payload rusak atau kunci salah.")

    if output_path is None:
        output_path = header["filename"] or "extracted_payload.bin"
    Path(output_path).write_bytes(restored)
    return {
        "output": output_path,
        "filename": header["filename"],
        "size": len(restored),
        "flags": header["flags"],
    }


# ---------------------------------------------------------------------------
# ===== IMAGE : DCT (Frequency Domain) =====
# ---------------------------------------------------------------------------
def _dct_matrix(N: int = DCT_BLOCK) -> "np.ndarray":
    n = np.arange(N)
    k = n.reshape(-1, 1)
    C = np.cos(np.pi * (2 * n + 1) * k / (2 * N)) * np.sqrt(2.0 / N)
    C[0, :] = C[0, :] / np.sqrt(2.0)
    return C


def _dct2(block: "np.ndarray") -> "np.ndarray":
    C = _dct_matrix(block.shape[0])
    return C @ block @ C.T


def _idct2(coeff: "np.ndarray") -> "np.ndarray":
    C = _dct_matrix(coeff.shape[0])
    return C.T @ coeff @ C


def _quant_step(quality: int = 80) -> float:
    """Skala kuantisasi (semakin besar → perubahan lebih terlihat)."""
    quality = max(1, min(100, quality))
    return float(max(1, 101 - quality))


def image_dct_embed(image_path: str, payload_path: str, output_path: str,
                    key: Optional[bytes] = None, compress: bool = True,
                    quality: int = 80) -> dict:
    _require_pil()
    _require_numpy()

    img = Image.open(image_path).convert("L")
    arr = np.array(img, dtype=np.float64)
    h, w = arr.shape
    if h % DCT_BLOCK or w % DCT_BLOCK:
        raise ValueError(
            f"Dimensi gambar harus kelipatan {DCT_BLOCK}. Sekarang: {w}x{h}."
        )

    raw = Path(payload_path).read_bytes()
    processed, flags = _prepare_payload(raw, key, compress)
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    header = _build_header(Path(payload_path).name, len(processed), crc, flags)
    blob = header + processed
    bits = _bytes_to_bits_py(blob)

    br, bc = w // DCT_BLOCK, h // DCT_BLOCK
    total_blocks = br * bc
    if len(bits) > total_blocks:
        raise ValueError(
            f"Kapasitas DCT tidak cukup: butuh {len(bits)} blok, "
            f"tersedia {total_blocks} blok."
        )

    step = _quant_step(quality)
    idx = 0
    for by in range(bc):
        for bx in range(br):
            y0, x0 = by * DCT_BLOCK, bx * DCT_BLOCK
            block = arr[y0:y0 + DCT_BLOCK, x0:x0 + DCT_BLOCK].copy()
            coeff = _dct2(block)
            c = coeff[DCT_COEFF_MID, DCT_COEFF_MID]
            q = round(c / step) * step
            if idx < len(bits):
                if bits[idx]:
                    q += step
                coeff[DCT_COEFF_MID, DCT_COEFF_MID] = q
                idx += 1
            else:
                coeff[DCT_COEFF_MID, DCT_COEFF_MID] = q
            arr[y0:y0 + DCT_BLOCK, x0:x0 + DCT_BLOCK] = _idct2(coeff)

    result = np.clip(np.round(arr), 0, 255).astype(np.uint8)
    Image.fromarray(result, "L").save(output_path, format="PNG")
    return {
        "output": output_path,
        "bits_used": len(bits),
        "capacity_bits": total_blocks,
        "usage_ratio": round(len(bits) / total_blocks, 6),
    }


def image_dct_extract(image_path: str, output_path: Optional[str] = None,
                      key: Optional[bytes] = None, quality: int = 80) -> dict:
    _require_pil()
    _require_numpy()

    img = Image.open(image_path).convert("L")
    arr = np.array(img, dtype=np.float64)
    h, w = arr.shape
    br, bc = w // DCT_BLOCK, h // DCT_BLOCK
    step = _quant_step(quality)

    bits: list[int] = []
    for by in range(bc):
        for bx in range(br):
            y0, x0 = by * DCT_BLOCK, bx * DCT_BLOCK
            block = arr[y0:y0 + DCT_BLOCK, x0:x0 + DCT_BLOCK]
            coeff = _dct2(block)
            c = coeff[DCT_COEFF_MID, DCT_COEFF_MID]
            r = round(c / step)
            bits.append(1 if (r % 2) != 0 else 0)

    min_bits = 7 * 8
    if len(bits) < min_bits:
        raise ValueError("Gambar terlalu kecil untuk header DCT.")
    head = _bits_to_bytes_py(bits[:min_bits])
    magic, _v, _f = struct.unpack(_HEADER_FMT_PREFIX, head[:6])
    if magic != MAGIC:
        raise ValueError(
            "Payload DCT tidak terdeteksi. Pastikan parameter 'quality' sama."
        )
    fname_len = head[6]
    header_bits = (7 + fname_len + 14) * 8
    if len(bits) < header_bits:
        raise ValueError("Header DCT terpotong.")
    header, hdr_size = _parse_header(_bits_to_bytes_py(bits[:header_bits]))
    total_bits = hdr_size * 8 + header["payload_len"] * 8
    if len(bits) < total_bits:
        raise ValueError("Payload DCT terpotong.")
    payload = _bits_to_bytes_py(bits[hdr_size * 8:total_bits])
    restored = _restore_payload(payload, key, header["flags"])
    if (zlib.crc32(restored) & 0xFFFFFFFF) != header["crc32"]:
        raise ValueError("CRC32 mismatch — gambar dimodifikasi atau quality salah.")

    if output_path is None:
        output_path = header["filename"] or "extracted_payload.bin"
    Path(output_path).write_bytes(restored)
    return {
        "output": output_path,
        "filename": header["filename"],
        "size": len(restored),
        "flags": header["flags"],
    }


# ---------------------------------------------------------------------------
# ===== AUDIO WAV : LSB =====
# ---------------------------------------------------------------------------
def _read_wav(path: str) -> Tuple["np.ndarray", int, int, int]:
    """Return (samples_int16_1d_or_2d, n_channels, sampwidth, framerate)."""
    _require_numpy()
    with wave.open(path, "rb") as wf:
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        framerate = wf.getframerate()
        n_frames = wf.getnframes()
        raw = wf.readframes(n_frames)
    if sampwidth != 2:
        raise ValueError("Hanya mendukung WAV 16-bit PCM.")
    samples = np.frombuffer(raw, dtype="<i2").astype(np.int32)
    if n_channels > 1:
        samples = samples.reshape(-1, n_channels)
    return samples, n_channels, sampwidth, framerate


def _write_wav(path: str, samples: "np.ndarray", n_channels: int,
               sampwidth: int, framerate: int) -> None:
    _require_numpy()
    data = samples.astype("<i2").tobytes()
    with wave.open(path, "wb") as wf:
        wf.setnchannels(n_channels)
        wf.setsampwidth(sampwidth)
        wf.setframerate(framerate)
        wf.writeframes(data)


def audio_lsb_embed(audio_path: str, payload_path: str, output_path: str,
                    key: Optional[bytes] = None, compress: bool = True) -> dict:
    _require_numpy()

    samples, n_channels, sampwidth, framerate = _read_wav(audio_path)
    flat = samples.reshape(-1).copy().astype(np.int32)

    raw = Path(payload_path).read_bytes()
    processed, flags = _prepare_payload(raw, key, compress)
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    header = _build_header(Path(payload_path).name, len(processed), crc, flags)
    blob = header + processed
    bits = _bytes_to_bits_py(blob)

    capacity = flat.size
    if len(bits) > capacity:
        raise ValueError(
            f"Kapasitas audio tidak cukup. Butuh {len(bits)} bit, "
            f"tersedia {capacity} bit."
        )

    # clear LSB + sisipkan bit
    flat[:len(bits)] = (flat[:len(bits)] & ~1) | np.array(bits, dtype=np.int32)
    flat = np.clip(flat, -32768, 32767).astype(np.int16)
    if n_channels > 1:
        flat = flat.reshape(-1, n_channels)

    _write_wav(output_path, flat, n_channels, sampwidth, framerate)
    return {
        "output": output_path,
        "bits_used": len(bits),
        "capacity_bits": int(capacity),
        "usage_ratio": round(len(bits) / capacity, 6),
    }


def audio_lsb_extract(audio_path: str, output_path: Optional[str] = None,
                      key: Optional[bytes] = None) -> dict:
    _require_numpy()

    samples, _nc, _sw, _fr = _read_wav(audio_path)
    bits = (samples.reshape(-1) & 1).astype(np.uint8)

    min_bits = 7 * 8
    if len(bits) < min_bits:
        raise ValueError("Audio terlalu pendek.")
    head = _bits_to_bytes(bits[:min_bits])
    magic, _v, _f = struct.unpack(_HEADER_FMT_PREFIX, head[:6])
    if magic != MAGIC:
        raise ValueError("Payload audio tidak terdeteksi.")
    fname_len = head[6]
    header_bits = (7 + fname_len + 14) * 8
    if len(bits) < header_bits:
        raise ValueError("Header audio terpotong.")
    header, hdr_size = _parse_header(_bits_to_bytes(bits[:header_bits]))
    total_bits = hdr_size * 8 + header["payload_len"] * 8
    if len(bits) < total_bits:
        raise ValueError("Payload audio terpotong.")
    payload = _bits_to_bytes(bits[hdr_size * 8:total_bits])
    restored = _restore_payload(payload, key, header["flags"])
    if (zlib.crc32(restored) & 0xFFFFFFFF) != header["crc32"]:
        raise ValueError("CRC32 mismatch — audio rusak atau kunci salah.")

    if output_path is None:
        output_path = header["filename"] or "extracted_payload.bin"
    Path(output_path).write_bytes(restored)
    return {
        "output": output_path,
        "filename": header["filename"],
        "size": len(restored),
        "flags": header["flags"],
    }


# ---------------------------------------------------------------------------
# ===== AUDIO WAV : DFT (Frequency Domain) =====
# ---------------------------------------------------------------------------
def audio_dft_embed(audio_path: str, payload_path: str, output_path: str,
                    key: Optional[bytes] = None, compress: bool = True,
                    freq_bin: int = 1000, delta: float = 4.0) -> dict:
    _require_numpy()

    samples, n_channels, sampwidth, framerate = _read_wav(audio_path)
    mono = (samples.mean(axis=1) if n_channels > 1 else samples).astype(np.float64)
    n = mono.size

    raw = Path(payload_path).read_bytes()
    processed, flags = _prepare_payload(raw, key, compress)
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    header = _build_header(Path(payload_path).name, len(processed), crc, flags)
    blob = header + processed
    bits = _bytes_to_bits_py(blob)

    spec = np.fft.rfft(mono)
    mag = np.abs(spec)
    phase = np.angle(spec)

    if freq_bin <= 0 or freq_bin >= len(spec) - 1:
        raise ValueError(f"freq_bin harus 1..{len(spec) - 2}")
    if freq_bin + len(bits) >= len(spec):
        raise ValueError(
            f"Payload terlalu besar untuk DFT. Butuh {len(bits)} bin, "
            f"tersedia {len(spec) - freq_bin - 1}."
        )

    baseline = float(np.median(mag[freq_bin:freq_bin + len(bits)]))
    for i, b in enumerate(bits):
        target = baseline + (delta if b else -delta)
        spec[freq_bin + i] = target * np.exp(1j * phase[freq_bin + i])

    modified = np.fft.irfft(spec, n=n)
    peak = np.max(np.abs(modified))
    if peak > 32000:
        modified = modified * (32000.0 / peak)
    if n_channels > 1:
        modified = np.repeat(modified[:, None], n_channels, axis=1)

    _write_wav(output_path, np.round(modified), n_channels, sampwidth, framerate)
    return {
        "output": output_path,
        "bits_used": len(bits),
        "capacity_bits": len(spec) - freq_bin - 1,
        "freq_bin": freq_bin,
    }


def audio_dft_extract(audio_path: str, output_path: Optional[str] = None,
                      key: Optional[bytes] = None, freq_bin: int = 1000,
                      delta: float = 4.0) -> dict:
    _require_numpy()

    samples, n_channels, _sw, _fr = _read_wav(audio_path)
    mono = (samples.mean(axis=1) if n_channels > 1 else samples).astype(np.float64)
    spec = np.fft.rfft(mono)
    mag = np.abs(spec)

    if freq_bin <= 0 or freq_bin + 56 >= len(spec):
        raise ValueError("freq_bin tidak valid atau audio terlalu pendek.")
    baseline = float(np.median(mag[freq_bin:freq_bin + 56]))
    head = _bits_to_bytes_py(
        [1 if mag[freq_bin + i] >= baseline else 0 for i in range(56)]
    )
    magic, _v, _f = struct.unpack(_HEADER_FMT_PREFIX, head[:6])
    if magic != MAGIC:
        raise ValueError("Payload DFT tidak terdeteksi.")
    fname_len = head[6]
    needed = (7 + fname_len + 14) * 8
    if freq_bin + needed >= len(spec):
        raise ValueError("Header DFT terpotong.")
    baseline = float(np.median(mag[freq_bin:freq_bin + needed]))
    header_bits = [1 if mag[freq_bin + i] >= baseline else 0 for i in range(needed)]
    header, hdr_size = _parse_header(_bits_to_bytes_py(header_bits))

    total_bits = hdr_size * 8 + header["payload_len"] * 8
    if freq_bin + total_bits >= len(spec):
        raise ValueError("Payload DFT terpotong.")
    baseline = float(np.median(mag[freq_bin:freq_bin + total_bits]))
    payload_bits = [
        1 if mag[freq_bin + i] >= baseline else 0
        for i in range(hdr_size * 8, total_bits)
    ]
    payload = _bits_to_bytes_py(payload_bits)
    restored = _restore_payload(payload, key, header["flags"])
    if (zlib.crc32(restored) & 0xFFFFFFFF) != header["crc32"]:
        raise ValueError("CRC32 mismatch — audio DFT rusak atau kunci salah.")

    if output_path is None:
        output_path = header["filename"] or "extracted_payload.bin"
    Path(output_path).write_bytes(restored)
    return {
        "output": output_path,
        "filename": header["filename"],
        "size": len(restored),
        "flags": header["flags"],
    }


# ---------------------------------------------------------------------------
# Kapasitas helper
# ---------------------------------------------------------------------------
def capacity_report_image(image_path: str, mode: str = "lsb") -> dict:
    _require_pil()
    _require_numpy()
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img)
    h, w, _ = arr.shape
    if mode == "lsb":
        cap_bits = arr.size
    elif mode == "dct":
        if h % DCT_BLOCK or w % DCT_BLOCK:
            raise ValueError(f"Dimensi harus kelipatan {DCT_BLOCK}.")
        cap_bits = (h // DCT_BLOCK) * (w // DCT_BLOCK)
    else:
        raise ValueError("mode harus 'lsb' atau 'dct'")
    return {
        "mode": mode,
        "dimensions": (w, h),
        "capacity_bits": int(cap_bits),
        "capacity_bytes": int(cap_bits // 8),
        "capacity_kib": round(cap_bits / 8 / 1024, 2),
    }


def capacity_report_audio(audio_path: str, mode: str = "lsb") -> dict:
    _require_numpy()
    samples, n_channels, _sw, _fr = _read_wav(audio_path)
    flat = samples.reshape(-1)
    if mode == "lsb":
        cap_bits = flat.size
    elif mode == "dft":
        n = samples.shape[0] if n_channels > 1 else samples.size
        cap_bits = max(0, n // 2 - 1001)
    else:
        raise ValueError("mode harus 'lsb' atau 'dft'")
    return {
        "mode": mode,
        "samples": int(flat.size),
        "capacity_bits": int(cap_bits),
        "capacity_bytes": int(cap_bits // 8),
        "capacity_kib": round(cap_bits / 8 / 1024, 2),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_json(obj: dict) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def _build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="steganography.py",
        description="LSB & Frequency Domain Steganography Engine (Image/Audio).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  # Embed payload ke gambar (LSB)
  python steganography.py embed-image cover.png secret.zip -o out.png --method lsb

  # Ekstrak dari gambar
  python steganography.py extract-image out.png -o secret.zip

  # DCT (butuh dimensi kelipatan 8)
  python steganography.py embed-image cover.png secret.zip -o out.png --method dct --quality 80

  # Audio LSB
  python steganography.py embed-audio track.wav secret.zip -o out.wav --method lsb

  # Audio DFT
  python steganography.py embed-audio track.wav secret.zip -o out.wav --method dft --freq-bin 1000

  # Dengan kunci (XOR stream)
  python steganography.py embed-image cover.png secret.zip -o out.png --key mypassword

  # Cek kapasitas
  python steganography.py capacity cover.png --type image --method lsb
""",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # embed-image
    sp = sub.add_parser("embed-image", help="Sisipkan payload ke gambar.")
    sp.add_argument("cover", help="Path gambar cover (PNG/BMP).")
    sp.add_argument("payload", help="Path payload (file apa saja).")
    sp.add_argument("-o", "--output", required=True, help="Path output gambar.")
    sp.add_argument("--method", choices=["lsb", "dct"], default="lsb")
    sp.add_argument("--quality", type=int, default=80, help="Kualitas DCT (1-100).")
    sp.add_argument("--key", default=None, help="Kunci teks untuk enkripsi XOR.")
    sp.add_argument("--no-compress", action="store_true", help="Matikan kompresi zlib.")

    # extract-image
    sp = sub.add_parser("extract-image", help="Ekstrak payload dari gambar.")
    sp.add_argument("stego", help="Path gambar stego.")
    sp.add_argument("-o", "--output", default=None, help="Path output payload.")
    sp.add_argument("--method", choices=["lsb", "dct"], default="lsb")
    sp.add_argument("--quality", type=int, default=80)
    sp.add_argument("--key", default=None)

    # embed-audio
    sp = sub.add_parser("embed-audio", help="Sisipkan payload ke WAV 16-bit.")
    sp.add_argument("cover", help="Path WAV cover.")
    sp.add_argument("payload", help="Path payload.")
    sp.add_argument("-o", "--output", required=True, help="Path WAV output.")
    sp.add_argument("--method", choices=["lsb", "dft"], default="lsb")
    sp.add_argument("--freq-bin", type=int, default=1000)
    sp.add_argument("--delta", type=float, default=4.0)
    sp.add_argument("--key", default=None)
    sp.add_argument("--no-compress", action="store_true")

    # extract-audio
    sp = sub.add_parser("extract-audio", help="Ekstrak payload dari WAV.")
    sp.add_argument("stego", help="Path WAV stego.")
    sp.add_argument("-o", "--output", default=None, help="Path output payload.")
    sp.add_argument("--method", choices=["lsb", "dft"], default="lsb")
    sp.add_argument("--freq-bin", type=int, default=1000)
    sp.add_argument("--delta", type=float, default=4.0)
    sp.add_argument("--key", default=None)

    # capacity
    sp = sub.add_parser("capacity", help="Laporkan kapasitas media.")
    sp.add_argument("media", help="Path gambar atau WAV.")
    sp.add_argument("--type", choices=["image", "audio"], required=True)
    sp.add_argument("--method", default="lsb",
                    help="lsb/dct untuk image, lsb/dft untuk audio.")

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(argv)
    key = _key_bytes(getattr(args, "key", None))

    try:
        if args.command == "embed-image":
            if args.method == "lsb":
                res = image_lsb_embed(args.cover, args.payload, args.output,
                                      key=key, compress=not args.no_compress)
            else:
                res = image_dct_embed(args.cover, args.payload, args.output,
                                      key=key, compress=not args.no_compress,
                                      quality=args.quality)
            _print_json(res)

        elif args.command == "extract-image":
            if args.method == "lsb":
                res = image_lsb_extract(args.stego, args.output, key=key)
            else:
                res = image_dct_extract(args.stego, args.output, key=key,
                                        quality=args.quality)
            _print_json(res)

        elif args.command == "embed-audio":
            if args.method == "lsb":
                res = audio_lsb_embed(args.cover, args.payload, args.output,
                                      key=key, compress=not args.no_compress)
            else:
                res = audio_dft_embed(args.cover, args.payload, args.output,
                                      key=key, compress=not args.no_compress,
                                      freq_bin=args.freq_bin, delta=args.delta)
            _print_json(res)

        elif args.command == "extract-audio":
            if args.method == "lsb":
                res = audio_lsb_extract(args.stego, args.output, key=key)
            else:
                res = audio_dft_extract(args.stego, args.output, key=key,
                                        freq_bin=args.freq_bin, delta=args.delta)
            _print_json(res)

        elif args.command == "capacity":
            if args.type == "image":
                res = capacity_report_image(args.media, mode=args.method)
            else:
                res = capacity_report_audio(args.media, mode=args.method)
            _print_json(res)

        else:
            parser.error(f"Perintah tidak dikenal: {args.command}")
        return 0

    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())