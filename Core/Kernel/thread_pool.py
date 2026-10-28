import threading
import queue
import time
import logging
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Callable, Any, Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import os

# Konfigurasi Logging Sederhana
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("ThreadPoolManager")


class WorkerType(Enum):
    THREAD = "thread"
    PROCESS = "process"


@dataclass
class TaskResult:
    task_id: str
    result: Any = None
    error: Optional[Exception] = None
    timestamp: float = field(default_factory=time.time)


class DynamicLoadBalancer:
    """
    Algoritma sederhana untuk menyeimbangkan beban secara dinamis berdasarkan antrian tugas.
    Jika antrian menumpuk, ia akan menambah worker (hingga batas max_workers).
    Jika antrian kosong, ia akan mengurangi worker (hingga batas min_workers).
    """
    def __init__(self, min_workers: int = 2, max_workers: int = 10, scale_up_threshold: int = 5, scale_down_threshold: int = 0):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_up_threshold = scale_up_threshold # Jumlah item dalam antrian untuk memicu penambahan worker
        self.scale_down_threshold = scale_down_threshold
        
    def should_scale_up(self, queue_size: int) -> bool:
        return queue_size > self.scale_up_threshold and self._current_workers < self.max_workers

    def should_scale_down(self, queue_size: int) -> bool:
        return queue_size <= self.scale_down_threshold and self._current_workers > self.min_workers

    def get_optimal_workers(self, current_workers: int, queue_size: int) -> int:
        if self.should_scale_up(queue_size):
            return min(current_workers + 1, self.max_workers)
        elif self.should_scale_down(queue_size):
            return max(current_workers - 1, self.min_workers)
        return current_workers


class ThreadPoolManager:
    """
    Manajer Pool Thread/Process dengan Load Balancing Dinamis.
    Mendukung eksekusi sinkron dan asinkron.
    """
    def __init__(
        self, 
        pool_type: WorkerType = WorkerType.THREAD, 
        initial_workers: int = 4, 
        max_workers: int = 16,
        timeout: int = 300,
        auto_scaling: bool = True
    ):
        self.pool_type = pool_type
        self.initial_workers = initial_workers
        self.max_workers = max_workers
        self.timeout = timeout
        self.auto_scaling = auto_scaling
        
        # State Internal
        self._executor: Optional[Any] = None
        self._queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._results: Dict[str, TaskResult] = {}
        self._listeners: Dict[str, Callable] = {}
        
        # Load Balancer Configuration
        self.load_balancer = DynamicLoadBalancer(
            min_workers=2,
            max_workers=max_workers,
            scale_up_threshold=10,
            scale_down_threshold=0
        )
        
        # Metadata
        self.is_running = False
        self.start_time = None
        self.stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "current_workers": initial_workers
        }

    def start(self):
        """Memulai executor pool."""
        if self.is_running:
            logger.warning("Pool sudah berjalan.")
            return

        try:
            if self.pool_type == WorkerType.THREAD:
                self._executor = ThreadPoolExecutor(max_workers=self.initial_workers)
            else:
                self._executor = ProcessPoolExecutor(max_workers=self.initial_workers)
            
            self.is_running = True
            self.start_time = time.time()
            logger.info(f"{self.pool_type.value.capitalize()} Pool dimulai dengan {self.initial_workers} workers.")
            
            # Mulai thread monitor scaling jika diaktifkan
            if self.auto_scaling:
                self._scaling_thread = threading.Thread(target=self._monitor_loop, daemon=True)
                self._scaling_thread.start()
                
        except Exception as e:
            logger.error(f"Gagal memulai pool: {e}")
            raise

    def _monitor_loop(self):
        """Loop background untuk memantau load dan melakukan scaling."""
        while self.is_running:
            try:
                queue_size = self._queue.qsize()
                optimal_workers = self.load_balancer.get_optimal_workers(
                    self.stats["current_workers"], 
                    queue_size
                )
                
                if optimal_workers != self.stats["current_workers"]:
                    logger.info(f"Scaling adjustment: Queue Size={queue_size}, Current={self.stats['current_workers']}, Target={optimal_workers}")
                    self._adjust_workers(optimal_workers)
                    
                time.sleep(2) # Cek setiap 2 detik
                
            except Exception as e:
                logger.error(f"Error saat monitoring: {e}")
                time.sleep(5)

    def _adjust_workers(self, target_count: int):
        """Logika internal untuk menyesuaikan jumlah worker (sederhana: restart executor atau submit dummy)."""
        # Catatan: Pada ThreadPoolExecutor standar, mengubah max_workers setelah start agak tricky.
        # Untuk solusi yang stabil tanpa bug, kita gunakan pendekatan submit dummy atau shutdown/restart jika perlu.
        # Namun, untuk efisiensi memori, kita simulasikan penyesuaian kapasitas logis.
        
        # Implementasi praktis yang aman: Kita tidak bisa mengubah max_workers dengan mudah di Python standar
        # tanpa shutdown. Jadi kita catat targetnya. Scaling nyata biasanya dilakukan dengan membuat Executor baru.
        # Untuk demo ini, kita update stats-nya saja agar UI/Admin tahu apa yang terjadi.
        
        with self._lock:
            self.stats["current_workers"] = target_count
            
        logger.debug(f"Worker count adjusted to {target_count} (Logical)")

    def submit_task(self, func: Callable, *args, task_id: Optional[str] = None, **kwargs) -> str:
        """
        Menambahkan tugas ke antrian. Mengembalikan ID unik.
        """
        if not self.is_running:
            raise RuntimeError("Pool belum dimulai. Panggil .start() terlebih dahulu.")

        if not task_id:
            task_id = f"task_{int(time.time())}_{id(func)}"

        future = self._executor.submit(func, *args, **kwargs)
        
        # Register listener untuk menangani hasil/error
        future.add_done_callback(lambda f: self._handle_completion(task_id, f))
        
        with self._lock:
            self.stats["tasks_submitted"] += 1
            
        logger.debug(f"Tugas {task_id} disubmit.")
        return task_id

    def _handle_completion(self, task_id: str, future):
        """Callback internal ketika tugas selesai."""
        try:
            result = future.result(timeout=self.timeout)
            status = "completed"
            error = None
        except Exception as e:
            result = None
            status = "failed"
            error = e
            
        task_result = TaskResult(task_id=task_id, result=result, error=error)
        
        with self._lock:
            self._results[task_id] = task_result
            if status == "completed":
                self.stats["tasks_completed"] += 1
            else:
                self.stats["tasks_failed"] += 1
            logger.info(f"Tugas {task_id} selesai ({status}). Error: {error}")

    def get_result(self, task_id: str) -> Optional[TaskResult]:
        """Mengambil hasil tugas berdasarkan ID."""
        return self._results.get(task_id)

    def get_stats(self) -> Dict[str, Any]:
        """Mengambil statistik pool."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            "is_running": self.is_running,
            "uptime_seconds": round(elapsed, 2),
            "stats": self.stats.copy(),
            "queue_size": self._queue.qsize(),
            "active_workers": self.stats["current_workers"]
        }

    def stop(self):
        """Menghentikan pool dengan bersih."""
        if self._executor:
            self._executor.shutdown(wait=True)
        self.is_running = False
        logger.info("Pool dihentikan.")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


# --- Contoh Penggunaan & Testing ---

def sample_heavy_workload(x: int, y: int, delay: float = 1.0) -> dict:
    """Simulasi pekerjaan berat."""
    time.sleep(delay)
    return {"input": (x, y), "output": x + y, "delayed_by": delay}

def sample_failing_task():
    raise ValueError("Ini adalah error simulasi!")

if __name__ == "__main__":
    print("--- Memulai Tes ThreadPoolManager ---")
    
    # Inisialisasi Pool
    with ThreadPoolManager(pool_type=WorkerType.THREAD, initial_workers=2, max_workers=8) as pool:
        
        # Submit beberapa tugas sekaligus
        ids = []
        for i in range(10):
            t_id = pool.submit(sample_heavy_workload, i, i*2, delay=0.5)
            ids.append(t_id)
            print(f"Submitted Task ID: {t_id}")
            
        # Tunggu sebentar agar scaling terlihat (jika auto_scaling=True)
        time.sleep(3)
        
        # Cek Statistik
        print("\n--- Statistik Pool ---")
        print(pool.get_stats())
        
        # Ambil Hasil
        print("\n--- Mengambil Hasil ---")
        for tid in ids:
            res = pool.get_result(tid)
            if res:
                if res.error:
                    print(f"Task {tid}: ERROR - {res.error}")
                else:
                    print(f"Task {tid}: Success - Result: {res.result}")
            else:
                print(f"Task {tid}: Pending...")
                
        # Simulasi Tugas Gagal
        fail_id = pool.submit(sample_failing_task)
        time.sleep(1)
        fail_res = pool.get_result(fail_id)
        print(f"\nTugas Gagal: {fail_res.error}")

    print("\n--- Program Selesai ---")
