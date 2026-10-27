# memory_manager.py
# Secure Heap Management & Garbage Collection for Sensitive Buffers
# Python 3.8+
#
# Fitur:
# - SecureBuffer: buffer yang di-zero-kan saat dihapus (anti-forensic)
# - SecureArena: heap manager dengan tracking blok sensitif
# - Auto GC via weakref finalizer + context manager
# - Defensive programming: validasi input, thread-safety, zeroization berlapis
# - Deteksi double-free, use-after-free, dan kebocoran memori

from __future__ import annotations

import hmac
import secrets
import threading
import weakref
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


__all__ = [
    "SecureBuffer",
    "SecureArena",
    "MemoryManagerError",
    "UseAfterFreeError",
    "DoubleFreeError",
    "secure_zeroize",
]


# ============================================================
# Exception hierarchy
# ============================================================
class MemoryManagerError(Exception):
    """Base error untuk memory manager."""


class UseAfterFreeError(MemoryManagerError):
    """Raised ketika buffer diakses setelah dibebaskan."""


class DoubleFreeError(MemoryManagerError):
    """Raised ketika buffer dibebaskan dua kali."""


# ============================================================
# Low-level zeroization
# ============================================================
def secure_zeroize(buffer: bytearray) -> None:
    """
    Menimpa isi bytearray dengan nol menggunakan beberapa lapisan
    untuk mengurangi risiko dead-store elimination oleh optimizer.
    """
    if not isinstance(buffer, bytearray):
        raise TypeError("secure_zeroize expects bytearray")

    n = len(buffer)
    if n == 0:
        return

    # Lapisan 1: nol
    for i in range(n):
        buffer[i] = 0

    # Lapisan 2: pola pseudo-random (mencegah optimasi)
    for i in range(n):
        buffer[i] = secrets.randbelow(256)

    # Lapisan 3: nol final
    for i in range(n):
        buffer[i] = 0


# ============================================================
# SecureBuffer
# ============================================================
class SecureBuffer:
    """
    Buffer sensitif yang:
    - Tidak bisa dibaca setelah dibebaskan (use-after-free terdeteksi)
    - Otomatis di-zeroize saat di-GC atau saat .free() dipanggil
    - Aman untuk multi-thread
    """

    __slots__ = (
        "_data",
        "_freed",
        "_lock",
        "_finalizer",
        "_id",
        "_debug_label",
        "__weakref__",
    )

    _counter: int = 0
    _counter_lock: threading.Lock = threading.Lock()

    def __init__(self, data: bytes, *, label: str = "") -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("SecureBuffer data must be bytes-like")

        raw = bytes(data)  # salinan defensif
        self._data: bytearray = bytearray(raw)
        self._freed: bool = False
        self._lock: threading.RLock = threading.RLock()
        self._id: int = SecureBuffer._next_id()
        self._debug_label: str = label

        # Finalizer: pastikan zeroization walau user lupa free()
        self._finalizer = weakref.finalize(
            self, SecureBuffer._finalize_cb, self._data
        )

    # -- internal -------------------------------------------------
    @classmethod
    def _next_id(cls) -> int:
        with cls._counter_lock:
            cls._counter += 1
            return cls._counter

    @staticmethod
    def _finalize_cb(data: bytearray) -> None:
        try:
            secure_zeroize(data)
        except Exception:
            # jangan pernah raise di finalizer
            pass

    def _ensure_alive(self) -> None:
        if self._freed:
            raise UseAfterFreeError(
                f"SecureBuffer#{self._id} accessed after free()"
            )

    # -- public API ----------------------------------------------
    @property
    def id(self) -> int:
        return self._id

    @property
    def label(self) -> str:
        return self._debug_label

    @property
    def size(self) -> int:
        with self._lock:
            self._ensure_alive()
            return len(self._data)

    @property
    def is_freed(self) -> bool:
        return self._freed

    def copy_bytes(self) -> bytes:
        """Kembalikan salinan immutable. Caller bertanggung jawab menghapus."""
        with self._lock:
            self._ensure_alive()
            return bytes(self._data)

    def view(self) -> memoryview:
        """Kembalikan memoryview read-only. Invalid setelah free()."""
        with self._lock:
            self._ensure_alive()
            return memoryview(self._data).toreadonly()

    def constant_time_equals(self, other: bytes) -> bool:
        if not isinstance(other, (bytes, bytearray, memoryview)):
            raise TypeError("other must be bytes-like")
        with self._lock:
            self._ensure_alive()
            return hmac.compare_digest(bytes(self._data), bytes(other))

    def free(self) -> None:
        with self._lock:
            if self._freed:
                raise DoubleFreeError(
                    f"SecureBuffer#{self._id} double free"
                )
            secure_zeroize(self._data)
            self._freed = True
            if self._finalizer.alive:
                self._finalizer.detach()

    # -- context manager -----------------------------------------
    def __enter__(self) -> "SecureBuffer":
        with self._lock:
            self._ensure_alive()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        with self._lock:
            if not self._freed:
                secure_zeroize(self._data)
                self._freed = True
                if self._finalizer.alive:
                    self._finalizer.detach()
        return False

    # -- repr -----------------------------------------------------
    def __repr__(self) -> str:
        state = "freed" if self._freed else "alive"
        return f"<SecureBuffer#{self._id} {state} len={len(self._data)}>"

    # -- mencegah pickle/copy tidak sengaja -----------------------
    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError("SecureBuffer cannot be pickled")

    def __copy__(self) -> "SecureBuffer":
        raise TypeError("SecureBuffer cannot be copied; use copy_bytes()")

    def __deepcopy__(self, memo: Optional[Dict[int, Any]]) -> "SecureBuffer":
        raise TypeError("SecureBuffer cannot be deep-copied; use copy_bytes()")


# ============================================================
# SecureArena — heap manager
# ============================================================
@dataclass
class _BlockRecord:
    buffer: SecureBuffer = field()
    tag: str = ""


class SecureArena:
    """
    Manajer heap untuk buffer sensitif.

    Fitur:
    - alokasi via allocate()
    - pembebasan eksplisit via free(buf)
    - free_all() dengan zeroization
    - statistik & leak detection
    - thread-safe
    """

    __slots__ = ("_blocks", "_lock", "_name", "_closed", "__weakref__")

    def __init__(self, *, name: str = "arena") -> None:
        if not isinstance(name, str):
            raise TypeError("name must be str")
        self._blocks: Dict[int, _BlockRecord] = {}
        self._lock: threading.RLock = threading.RLock()
        self._name: str = name
        self._closed: bool = False

    # -- internals -----------------------------------------------
    def _ensure_open(self) -> None:
        if self._closed:
            raise MemoryManagerError(
                f"SecureArena '{self._name}' sudah ditutup"
            )

    def _on_buffer_collected(self, block_id: int) -> None:
        with self._lock:
            # buffer sudah di-zeroize oleh finalizer SecureBuffer
            self._blocks.pop(block_id, None)

    # -- allocation ----------------------------------------------
    def allocate(self, data: bytes, *, tag: str = "") -> SecureBuffer:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        if not isinstance(tag, str):
            raise TypeError("tag must be str")
        with self._lock:
            self._ensure_open()
            buf = SecureBuffer(data, label=tag)
            self._blocks[buf.id] = _BlockRecord(buffer=buf, tag=tag)
            # weakref callback: kalau user buang referensi, arena sadar
            weakref.finalize(buf, self._on_buffer_collected, buf.id)
            return buf

    # -- freeing -------------------------------------------------
    def free(self, buf: SecureBuffer) -> None:
        if not isinstance(buf, SecureBuffer):
            raise TypeError("free expects SecureBuffer")
        with self._lock:
            self._ensure_open()
            rec = self._blocks.get(buf.id)
            if rec is None:
                raise UseAfterFreeError(
                    f"buffer#{buf.id} bukan milik arena atau sudah dibebaskan"
                )
            buf.free()
            del self._blocks[buf.id]

    def free_all(self) -> None:
        """Zeroize semua buffer yang masih hidup."""
        with self._lock:
            errors: list = []
            for block_id, rec in list(self._blocks.items()):
                try:
                    if not rec.buffer.is_freed:
                        rec.buffer.free()
                except Exception as e:
                    errors.append(e)
                finally:
                    self._blocks.pop(block_id, None)
            if errors:
                raise MemoryManagerError(
                    f"{len(errors)} error saat free_all: {errors[0]!r}"
                )

    # -- lifecycle -----------------------------------------------
    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self.free_all()
            self._closed = True

    def __enter__(self) -> "SecureArena":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    # -- observability -------------------------------------------
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            alive = 0
            total_bytes = 0
            for rec in self._blocks.values():
                if not rec.buffer.is_freed:
                    alive += 1
                    total_bytes += rec.buffer.size
            return {
                "name": self._name,
                "closed": self._closed,
                "tracked_blocks": len(self._blocks),
                "alive_blocks": alive,
                "total_bytes": total_bytes,
                "tags": [r.tag for r in self._blocks.values()],
            }

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"<SecureArena name={s['name']!r} alive={s['alive_blocks']} "
            f"bytes={s['total_bytes']} closed={s['closed']}>"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError("SecureArena cannot be pickled")


# ============================================================
# Demo / self-test
# ============================================================
def _self_test() -> None:
    print("== Self-test memory_manager ==")

    # 1. Basic alloc/free
    with SecureArena(name="demo") as arena:
        b1 = arena.allocate(b"super-secret-key-1234", tag="kek")
        assert b1.size == len(b"super-secret-key-1234")
        assert b1.copy_bytes() == b"super-secret-key-1234"
        assert b1.constant_time_equals(b"super-secret-key-1234")
        assert not b1.is_freed
        arena.free(b1)
        assert b1.is_freed

        # use-after-free
        try:
            b1.copy_bytes()
            raise AssertionError("expected UseAfterFreeError")
        except UseAfterFreeError:
            pass

        # double free
        try:
            b1.free()
            raise AssertionError("expected DoubleFreeError")
        except DoubleFreeError:
            pass

        # 2. Context manager per-buffer
        with arena.allocate(b"otp-42", tag="otp") as b2:
            assert b2.copy_bytes() == b"otp-42"
        try:
            b2.copy_bytes()
            raise AssertionError("expected UseAfterFreeError")
        except UseAfterFreeError:
            pass

        # 3. Multiple blocks & free_all
        bufs = [arena.allocate(f"blob-{i}".encode()) for i in range(5)]
        assert arena.stats()["alive_blocks"] == 5
        arena.free_all()
        assert arena.stats()["alive_blocks"] == 0
        for b in bufs:
            assert b.is_freed

    # 4. Zeroization check
    data = bytearray(b"SECRET!!")
    secure_zeroize(data)
    assert bytes(data) == b"\x00" * len(b"SECRET!!")

    # 5. Arena closed
    try:
        arena.allocate(b"x")
        raise AssertionError("expected MemoryManagerError")
    except MemoryManagerError:
        pass

    # 6. Pickle / copy protection
    with SecureArena() as a2:
        b3 = a2.allocate(b"data")
        import pickle
        try:
            pickle.dumps(b3)
            raise AssertionError("expected TypeError on pickle")
        except TypeError:
            pass
        try:
            __import__("copy").copy(b3)
            raise AssertionError("expected TypeError on copy")
        except TypeError:
            pass

    print("OK: semua test lulus")


if __name__ == "__main__":
    _self_test()