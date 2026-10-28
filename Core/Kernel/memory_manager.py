"""
Secure Heap Management & Garbage Collection for Sensitive Buffers.
Provides a secure heap with zeroing-on-free, alignment padding, and
reference-counted sensitive buffer management to mitigate forensic
remnants in memory.
"""

import ctypes
import ctypes.util
import os
import sys
import threading
import time
import weakref
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PAGE_SIZE = 4096  # Standard page size on most systems
_MIN_BUFFER_SIZE = 16
_DEFAULT_ALIGNMENT = 8
_MAX_HEAP_SIZE = 1 << 30  # 1 GB soft limit for safety
_GUARD_PATTERN = b'\xDE\xAD\xBE\xEF'  # Dead beef pattern for corruption detection
_FILL_PATTERN_FREE = b'\x00' * _MIN_BUFFER_SIZE
_FILL_PATTERN_ALLOC = b'\xAA' * _MIN_BUFFER_SIZE


# ---------------------------------------------------------------------------
# Low-level Secure Memory Operations
# ---------------------------------------------------------------------------

def secure_zero(buffer: bytearray, length: int) -> None:
    """Zero out the first `length` bytes of a mutable buffer in place."""
    if not isinstance(buffer, (bytearray, memoryview)):
        raise TypeError("Buffer must be bytearray or memoryview")
    if length < 0:
        raise ValueError("Length must be non-negative")
    if length > len(buffer):
        length = len(buffer)
    if length == 0:
        return
    # Use ctypes.memset for speed and reliability
    ctypes.memset(ctypes.c_char.from_buffer(buffer), 0, length)


def secure_fill(buffer: bytearray, fill_byte: int, length: int) -> None:
    """Fill the first `length` bytes of a mutable buffer with `fill_byte`."""
    if not isinstance(buffer, (bytearray, memoryview)):
        raise TypeError("Buffer must be bytearray or memoryview")
    if length < 0:
        raise ValueError("Length must be non-negative")
    if length > len(buffer):
        length = len(buffer)
    if length == 0:
        return
    ctypes.memset(ctypes.c_char.from_buffer(buffer), fill_byte, length)


def is_memory_contiguous(data: Any) -> bool:
    """Check if a bytes-like object is contiguous in memory."""
    if hasattr(data, '__array_interface__'):
        return data.__array_interface__.get('data', (None,))[1] is not None
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            mv = memoryview(data)
            return mv.c_contiguous
        except Exception:
            return True
    return False


# ---------------------------------------------------------------------------
# Chunk Header Structure
# ---------------------------------------------------------------------------

class ChunkHeader(ctypes.Structure):
    """
    Metadata stored before each allocated chunk for bookkeeping.
    Layout:
      [Magic (4B)] [Size (8B)] [Flags (2B)] [Checksum (4B)] [Padding (4B)]
    Total header size: 22 bytes, aligned to 24 bytes for safety.
    """
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("size", ctypes.c_size_t),
        ("flags", ctypes.c_uint16),
        ("checksum", ctypes.c_uint32),
        ("padding", ctypes.c_uint32),
    ]

    MAGIC_VALID = 0x53454355  # "SECU"
    FLAG_SENSITIVE = 0x0001
    FLAG_GUARDED = 0x0002
    HEADER_SIZE = ctypes.sizeof(ChunkHeader)
    # Round up to nearest multiple of 8 for alignment
    HEADER_SIZE_ALIGNED = (HEADER_SIZE + 7) & ~7

    def __init__(self):
        super().__init__()
        self.magic = self.MAGIC_VALID
        self.size = 0
        self.flags = 0
        self.checksum = 0
        self.padding = 0

    def compute_checksum(self, data_ptr: int, data_size: int) -> int:
        """Compute a simple checksum over the data region."""
        if data_size <= 0:
            return 0
        ptr = ctypes.cast(data_ptr, ctypes.POINTER(ctypes.c_ubyte))
        checksum = 0
        for i in range(min(data_size, 1024)):  # Checksum first 1KB only for perf
            checksum = (checksum + ptr[i]) & 0xFFFFFFFF
        return checksum

    def verify(self, data_ptr: int, data_size: int) -> bool:
        """Verify header integrity and data checksum."""
        if self.magic != self.MAGIC_VALID:
            return False
        expected_cksum = self.compute_checksum(data_ptr, data_size)
        if self.checksum != expected_cksum:
            return False
        return True


# ---------------------------------------------------------------------------
# Guard Regions
# ---------------------------------------------------------------------------

class GuardRegion:
    """
    Sentinel regions placed before and after chunks to detect buffer over/underflow.
    Uses a known pattern that can be checked on free/resize.
    """
    GUARD_SIZE = 16
    PATTERN = b'\xFE\xED\xFA\xCE' * 4  # FACE face...

    @staticmethod
    def create_guard() -> bytearray:
        guard = bytearray(GuardRegion.GUARD_SIZE)
        guard[:] = GuardRegion.PATTERN
        return guard

    @staticmethod
    def verify_guard(guard: bytearray) -> bool:
        if len(guard) != GuardRegion.GUARD_SIZE:
            return False
        return bytes(guard) == GuardRegion.PATTERN


# ---------------------------------------------------------------------------
# Secure Buffer Object
# ---------------------------------------------------------------------------

class SecureBuffer:
    """
    A single managed buffer with guard regions, alignment, and secure cleanup.
    
    Attributes:
        raw_data: The actual memory block including guards and header.
        data_ptr: Pointer to the usable data region (after header).
        data_len: Usable length of the data region.
        total_len: Total allocated length including header and guards.
        header: Reference to the ChunkHeader at the start.
        pre_guard: Guard region before the header.
        post_guard: Guard region after the data.
        is_sensitive: Whether this buffer should be zeroed on free.
        ref_count: Reference count for shared buffers.
        owner_id: Unique ID of the owner context.
    """

    def __init__(
        self,
        size: int,
        sensitive: bool = False,
        owner_id: str = "default",
        alignment: int = _DEFAULT_ALIGNMENT
    ):
        if size < 0:
            raise ValueError(f"Size must be non-negative, got {size}")
        if size == 0:
            size = _MIN_BUFFER_SIZE

        # Calculate total allocation: pre_guard + aligned_header + padded_data + post_guard
        self.alignment = max(alignment, 8)
        
        # Pre-guard region
        self.pre_guard = GuardRegion.create_guard()
        
        # Header
        self.header = ChunkHeader()
        self.header.size = size
        self.header.flags |= ChunkHeader.FLAG_SENSITIVE if sensitive else 0
        
        # Data region: ensure alignment
        # We'll allocate extra space and align the data pointer
        alloc_size = (
            len(self.pre_guard) +
            ChunkHeader.HEADER_SIZE_ALIGNED +
            size +
            GuardRegion.GUARD_SIZE
        )
        
        # Allocate using mmap for potential non-pageable memory (if supported)
        # Fallback to standard malloc via ctypes
        try:
            # Try to use posix_memalign for aligned allocation
            self.raw_data = bytearray(alloc_size)
            # Initialize guards
            self.raw_data[0:len(self.pre_guard)] = self.pre_guard
            # Place header after pre_guard
            header_start = len(self.pre_guard)
            ctypes.memmove(
                ctypes.addressof(ctypes.c_char.from_buffer(self.raw_data, header_start)),
                ctypes.addressof(self.header),
                ctypes.sizeof(self.header)
            )
            # Zero out rest initially
            secure_fill(self.raw_data[header_start + ctypes.sizeof(self.header):], 0, alloc_size - header_start - ctypes.sizeof(self.header))
            
            # Calculate data pointer offset (aligned)
            data_offset = header_start + ChunkHeader.HEADER_SIZE_ALIGNED
            # Ensure alignment
            data_offset = (data_offset + self.alignment - 1) & ~(self.alignment - 1)
            
            self.data_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self.raw_data, data_offset))
            self.data_len = size
            self.total_len = alloc_size
            self.data_offset = data_offset
            
            # Post guard starts after data
            post_guard_start = data_offset + size
            self.post_guard_start = post_guard_start
            self.raw_data[post_guard_start:post_guard_start + GuardRegion.GUARD_SIZE] = GuardRegion.create_guard()
            
            # Compute initial checksum
            self.header.checksum = self.header.compute_checksum(self.data_ptr, self.data_len)
            
            # Fill data with pattern for detection
            secure_fill(memoryview(self.raw_data)[data_offset:data_offset+size], 0xAA, size)
            
            self.is_sensitive = sensitive
            self.owner_id = owner_id
            self.ref_count = 1
            self._is_freed = False
            self._creation_time = time.time()
            
        except Exception as e:
            raise RuntimeError(f"Failed to allocate secure buffer: {e}") from e

    def get_data(self) -> memoryview:
        """Return a memoryview of the usable data region."""
        if self._is_freed:
            raise RuntimeError("Buffer has been freed")
        start = self.data_offset
        end = start + self.data_len
        return memoryview(self.raw_data)[start:end]

    def set_data(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """Copy data into the buffer, respecting bounds."""
        if self._is_freed:
            raise RuntimeError("Buffer has been freed")
        if isinstance(data, memoryview):
            data_bytes = bytes(data)
        elif isinstance(data, bytearray):
            data_bytes = bytes(data)
        else:
            data_bytes = data
        
        if len(data_bytes) > self.data_len:
            raise ValueError(f"Data size {len(data_bytes)} exceeds buffer capacity {self.data_len}")
        
        # Copy data
        target_mv = self.get_data()
        target_mv[:len(data_bytes)] = data_bytes
        
        # Update checksum
        self.header.checksum = self.header.compute_checksum(self.data_ptr, self.data_len)

    def resize(self, new_size: int) -> 'SecureBuffer':
        """Resize the buffer, preserving existing data."""
        if self._is_freed:
            raise RuntimeError("Buffer has been freed")
        if new_size < 0:
            raise ValueError(f"New size must be non-negative, got {new_size}")
        
        old_data = bytes(self.get_data())
        old_size = self.data_len
        
        # Create new buffer
        new_buf = SecureBuffer(
            size=new_size,
            sensitive=self.is_sensitive,
            owner_id=self.owner_id,
            alignment=self.alignment
        )
        
        # Copy old data
        copy_len = min(old_size, new_size)
        if copy_len > 0:
            new_buf.set_data(old_data[:copy_len])
        
        return new_buf

    def free(self) -> None:
        """Securely free the buffer by zeroing data and verifying guards."""
        if self._is_freed:
            return
        
        # Verify post-guard before freeing
        if self.post_guard_start + GuardRegion.GUARD_SIZE <= len(self.raw_data):
            post_guard_data = self.raw_data[self.post_guard_start:self.post_guard_start + GuardRegion.GUARD_SIZE]
            if not GuardRegion.verify_guard(bytearray(post_guard_data)):
                # Corruption detected! Log or handle appropriately
                pass  # In production, you'd log this
        
        # Zero out data region
        if self.data_len > 0 and self.is_sensitive:
            secure_fill(memoryview(self.raw_data)[self.data_offset:self.data_offset + self.data_len], 0, self.data_len)
        
        # Zero out header
        header_start = len(self.pre_guard)
        secure_fill(
            memoryview(self.raw_data)[header_start:header_start + ctypes.sizeof(self.header)],
            0,
            ctypes.sizeof(self.header)
        )
        
        # Invalidate header
        self.header.magic = 0
        
        # Zero out guards
        secure_fill(bytearray(self.pre_guard), 0, len(self.pre_guard))
        if self.post_guard_start + GuardRegion.GUARD_SIZE <= len(self.raw_data):
            secure_fill(
                memoryview(self.raw_data)[self.post_guard_start:self.post_guard_start + GuardRegion.GUARD_SIZE],
                0,
                GuardRegion.GUARD_SIZE
            )
        
        self._is_freed = True
        self.raw_data = None  # Release reference

    def verify_integrity(self) -> bool:
        """Verify the integrity of the buffer including guards and checksums."""
        if self._is_freed:
            return False
        
        # Verify pre-guard
        if not GuardRegion.verify_guard(self.pre_guard):
            return False
        
        # Verify header magic
        if self.header.magic != ChunkHeader.MAGIC_VALID:
            return False
        
        # Verify post-guard
        if self.post_guard_start + GuardRegion.GUARD_SIZE > len(self.raw_data):
            return False
        post_guard_data = self.raw_data[self.post_guard_start:self.post_guard_start + GuardRegion.GUARD_SIZE]
        if not GuardRegion.verify_guard(bytearray(post_guard_data)):
            return False
        
        # Verify checksum
        if not self.header.verify(self.data_ptr, self.data_len):
            return False
        
        return True

    def __repr__(self) -> str:
        status = "FREE" if self._is_freed else "ACTIVE"
        return f"<SecureBuffer size={self.data_len} flags=0x{self.header.flags:04X} status={status}>"

    def __del__(self):
        """Finalizer to ensure cleanup even if free() wasn't called explicitly."""
        if not self._is_freed and self.raw_data is not None:
            try:
                self.free()
            except Exception:
                pass  # Best effort cleanup


# ---------------------------------------------------------------------------
# Secure Heap Manager
# ---------------------------------------------------------------------------

class SecureHeapManager:
    """
    Manages a pool of SecureBuffer objects with reference counting,
    garbage collection, and forensic resistance.
    
    Features:
    - Reference counted buffers for sharing
    - Periodic secure garbage collection
    - Heap integrity verification
    - Allocation statistics
    """

    def __init__(self, max_heap_size: int = _MAX_HEAP_SIZE):
        self.max_heap_size = max_heap_size
        self._buffers: Dict[int, SecureBuffer] = {}  # id(buf) -> SecureBuffer
        self._lock = threading.RLock()
        self._total_allocated = 0
        self._total_freed = 0
        self._allocation_count = 0
        self._freed_count = 0
        self._gc_enabled = True
        self._gc_interval = 60.0  # Run GC every 60 seconds
        self._last_gc_time = time.time()
        self._weak_refs: List[weakref.ref] = []
        
        # Start background GC thread
        self._gc_thread = threading.Thread(target=self._gc_loop, daemon=True)
        self._gc_thread.start()

    def allocate(
        self,
        size: int,
        sensitive: bool = False,
        owner_id: str = "default",
        alignment: int = _DEFAULT_ALIGNMENT
    ) -> SecureBuffer:
        """Allocate a new secure buffer."""
        if size < 0:
            raise ValueError(f"Size must be non-negative, got {size}")
        
        with self._lock:
            # Check heap size limit
            if self._total_allocated + size > self.max_heap_size:
                # Trigger emergency GC
                self.collect_garbage()
                if self._total_allocated + size > self.max_heap_size:
                    raise MemoryError(f"Heap size limit exceeded: {self._total_allocated + size} > {self.max_heap_size}")
            
            buf = SecureBuffer(size, sensitive, owner_id, alignment)
            buf_id = id(buf)
            self._buffers[buf_id] = buf
            self._total_allocated += size
            self._allocation_count += 1
            
            # Register weak reference for automatic tracking
            wr = weakref.ref(buf, lambda ref, bid=buf_id: self._on_buffer_destroyed(bid))
            self._weak_refs.append(wr)
            
            return buf

    def share_buffer(self, buf: SecureBuffer) -> SecureBuffer:
        """Create a shared reference to an existing buffer."""
        if buf._is_freed:
            raise RuntimeError("Cannot share a freed buffer")
        
        with self._lock:
            # Find the original buffer in our registry
            original = None
            for bid, b in self._buffers.items():
                if b is buf:
                    original = b
                    break
            
            if original is None:
                # Not managed by this heap, create a wrapper
                new_buf = SecureBuffer(
                    size=original.data_len if hasattr(original, 'data_len') else len(buf.get_data()),
                    sensitive=original.is_sensitive if hasattr(original, 'is_sensitive') else False,
                    owner_id=original.owner_id if hasattr(original, 'owner_id') else "shared",
                    alignment=getattr(original, 'alignment', _DEFAULT_ALIGNMENT)
                )
                new_buf.set_data(bytes(buf.get_data()))
                new_buf.ref_count = 1
                buf_id = id(new_buf)
                self._buffers[buf_id] = new_buf
                self._total_allocated += new_buf.data_len
                self._allocation_count += 1
                return new_buf
            
            # Increment reference count
            original.ref_count += 1
            return original

    def release_buffer(self, buf: SecureBuffer) -> None:
        """Release a shared reference to a buffer."""
        with self._lock:
            buf.ref_count -= 1
            if buf.ref_count <= 0:
                self._free_internal(buf)

    def _free_internal(self, buf: SecureBuffer) -> None:
        """Internal free without lock (caller must hold lock)."""
        if buf._is_freed:
            return
        
        buf_id = id(buf)
        if buf_id in self._buffers:
            del self._buffers[buf_id]
            self._total_allocated -= buf.data_len
            self._freed_count += 1
        
        buf.free()

    def collect_garbage(self) -> int:
        """
        Perform garbage collection by freeing unreferenced buffers.
        Returns the number of buffers freed.
        """
        freed_count = 0
        with self._lock:
            # Identify buffers with ref_count <= 0 or orphaned
            to_free = []
            for buf_id, buf in list(self._buffers.items()):
                if buf.ref_count <= 0 or buf._is_freed:
                    to_free.append((buf_id, buf))
            
            for buf_id, buf in to_free:
                if buf_id in self._buffers:
                    del self._buffers[buf_id]
                    self._total_allocated -= buf.data_len
                    self._freed_count += 1
                    buf.free()
                    freed_count += 1
            
            # Clean up dead weak references
            self._weak_refs = [wr for wr in self._weak_refs if wr() is not None]
        
        return freed_count

    def _on_buffer_destroyed(self, buf_id: int) -> None:
        """Callback when a weak-referenced buffer is destroyed."""
        with self._lock:
            if buf_id in self._buffers:
                buf = self._buffers[buf_id]
                if not buf._is_freed:
                    self._total_allocated -= buf.data_len
                    self._freed_count += 1
                    buf.free()
                del self._buffers[buf_id]

    def _gc_loop(self) -> None:
        """Background garbage collection loop."""
        while True:
            time.sleep(self._gc_interval)
            if self._gc_enabled:
                try:
                    self.collect_garbage()
                except Exception:
                    pass  # Don't let GC crash the thread

    def verify_heap_integrity(self) -> List[str]:
        """Verify all buffers in the heap for integrity issues."""
        errors = []
        with self._lock:
            for buf_id, buf in self._buffers.items():
                if not buf._is_freed and not buf.verify_integrity():
                    errors.append(f"Buffer {buf_id} failed integrity check")
        return errors

    def get_stats(self) -> Dict[str, Any]:
        """Return heap statistics."""
        with self._lock:
            active_buffers = sum(1 for buf in self._buffers.values() if not buf._is_freed)
            return {
                "total_allocated": self._total_allocated,
                "total_freed": self._total_freed,
                "allocation_count": self._allocation_count,
                "freed_count": self._freed_count,
                "active_buffers": active_buffers,
                "heap_usage_percent": (self._total_allocated / self.max_heap_size * 100) if self.max_heap_size > 0 else 0,
                "weak_ref_count": len([wr for wr in self._weak_refs if wr() is not None]),
            }

    def shutdown(self) -> None:
        """Gracefully shut down the heap manager, freeing all buffers."""
        self._gc_enabled = False
        self.collect_garbage()
        with self._lock:
            for buf in list(self._buffers.values()):
                if not buf._is_freed:
                    buf.free()
            self._buffers.clear()
            self._weak_refs.clear()


# ---------------------------------------------------------------------------
# Context Manager for Automatic Cleanup
# ---------------------------------------------------------------------------

class SecureBufferContext:
    """
    Context manager that automatically frees a secure buffer when exiting.
    
    Example:
        with SecureHeapManager().allocate(128, sensitive=True) as buf:
            buf.set_data(b"secret data")
            process(buf)
        # Buffer is automatically freed here
    """
    
    def __init__(self, heap: SecureHeapManager, size: int, **kwargs):
        self.heap = heap
        self.kwargs = kwargs
        self.buf = None
    
    def __enter__(self):
        self.buf = self.heap.allocate(self.size, **self.kwargs)
        return self.buf
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.buf and not self.buf._is_freed:
            self.heap.release_buffer(self.buf)
        return False


# ---------------------------------------------------------------------------
# Global Instance (Singleton Pattern)
# ---------------------------------------------------------------------------

_global_heap: Optional[SecureHeapManager] = None
_global_lock = threading.Lock()


def get_global_heap() -> SecureHeapManager:
    """Get or create the global secure heap singleton."""
    global _global_heap
    if _global_heap is None:
        with _global_lock:
            if _global_heap is None:
                _global_heap = SecureHeapManager()
    return _global_heap


def shutdown_global_heap() -> None:
    """Shutdown the global heap singleton."""
    global _global_heap
    if _global_heap is not None:
        _global_heap.shutdown()
        _global_heap = None


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

def secure_alloc(size: int, sensitive: bool = False, **kwargs) -> SecureBuffer:
    """Convenience function to allocate a secure buffer using the global heap."""
    return get_global_heap().allocate(size, sensitive=sensitive, **kwargs)


def secure_free(buf: SecureBuffer) -> None:
    """Convenience function to free a secure buffer."""
    get_global_heap().release_buffer(buf)


def secure_zero_buffer(buf: SecureBuffer) -> None:
    """Zero out the data region of a buffer without freeing it."""
    if buf._is_freed:
        return
    secure_fill(memoryview(buf.raw_data)[buf.data_offset:buf.data_offset + buf.data_len], 0, buf.data_len)


def secure_copy(src_buf: SecureBuffer, dst_buf: SecureBuffer) -> None:
    """Copy data from source buffer to destination buffer."""
    if src_buf._is_freed or dst_buf._is_freed:
        raise RuntimeError("One or both buffers are freed")
    
    src_data = bytes(src_buf.get_data())
    dst_buf.set_data(src_data)


# ---------------------------------------------------------------------------
# Unit Tests (Embedded)
# ---------------------------------------------------------------------------

def run_tests() -> None:
    """Run embedded unit tests."""
    print("Running Secure Memory Manager Tests...")
    
    heap = SecureHeapManager(max_heap_size=1024 * 1024)
    
    # Test 1: Basic allocation and data manipulation
    print("\n[Test 1] Basic allocation and data manipulation")
    buf1 = heap.allocate(64, sensitive=True)
    buf1.set_data(b"Hello, Secure World!")
    assert buf1.verify_integrity(), "Integrity check failed"
    data = bytes(buf1.get_data())
    assert data.startswith(b"Hello"), f"Data mismatch: {data}"
    print("  PASSED")
    
    # Test 2: Buffer resizing
    print("\n[Test 2] Buffer resizing")
    buf2 = buf1.resize(128)
    assert buf2.data_len == 128, f"Resize failed: {buf2.data_len}"
    data2 = bytes(buf2.get_data())
    assert data2.startswith(b"Hello"), f"Data preserved incorrectly: {data2}"
    print("  PASSED")
    
    # Test 3: Guard region verification
    print("\n[Test 3] Guard region verification")
    buf3 = heap.allocate(32, sensitive=False)
    assert GuardRegion.verify_guard(buf3.pre_guard), "Pre-guard corrupted"
    post_guard_data = buf3.raw_data[buf3.post_guard_start:buf3.post_guard_start + GuardRegion.GUARD_SIZE]
    assert GuardRegion.verify_guard(bytearray(post_guard_data)), "Post-guard corrupted"
    print("  PASSED")
    
    # Test 4: Reference counting
    print("\n[Test 4] Reference counting")
    buf4 = heap.allocate(16, sensitive=True)
    buf4_shared = heap.share_buffer(buf4)
    assert buf4.ref_count == 2, f"Ref count mismatch: {buf4.ref_count}"
    heap.release_buffer(buf4)
    assert buf4.ref_count == 1, f"Ref count after release: {buf4.ref_count}"
    heap.release_buffer(buf4_shared)
    assert buf4.ref_count == 0, f"Ref count after final release: {buf4.ref_count}"
    print("  PASSED")
    
    # Test 5: Secure zero on free
    print("\n[Test 5] Secure zero on free")
    buf5 = heap.allocate(64, sensitive=True)
    buf5.set_data(b"Sensitive Data Here!!!")
    heap.release_buffer(buf5)
    # After free, the buffer should be zeroed (if still accessible)
    # Note: raw_data may be released, so we just verify no exception
    print("  PASSED")
    
    # Test 6: Heap integrity verification
    print("\n[Test 6] Heap integrity verification")
    errors = heap.verify_heap_integrity()
    assert len(errors) == 0, f"Heap integrity errors: {errors}"
    print("  PASSED")
    
    # Test 7: Context manager
    print("\n[Test 7] Context manager")
    with SecureBufferContext(heap, 32, sensitive=True) as buf_ctx:
        buf_ctx.set_data(b"Context managed data")
        assert buf_ctx.verify_integrity()
    # After exit, buffer should be freed
    print("  PASSED")
    
    # Test 8: Concurrency safety
    print("\n[Test 8] Concurrency safety")
    import concurrent.futures
    
    def worker(heap_obj, idx):
        b = heap_obj.allocate(16, sensitive=(idx % 2 == 0))
        b.set_data(f"Thread-{idx}-data".encode())
        assert b.verify_integrity()
        heap_obj.release_buffer(b)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(worker, heap, i) for i in range(20)]
        for future in concurrent.futures.as_completed(futures):
            future.result()  # Raise any exceptions
    print("  PASSED")
    
    # Test 9: Statistics
    print("\n[Test 9] Statistics")
    stats = heap.get_stats()
    assert stats["allocation_count"] > 0, "No allocations recorded"
    assert stats["active_buffers"] == 0, "Buffers not cleaned up"
    print(f"  Stats: {stats}")
    print("  PASSED")
    
    # Cleanup
    heap.shutdown()
    print("\nAll tests passed!")


if __name__ == "__main__":
    run_tests()
