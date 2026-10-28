"""
main.py - Advanced CLI & TUI Dashboard Entry Point
"""

import asyncio
import random
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, DataTable, Log, Button, Label
from textual.binding import Binding
from textual.reactive import reactive


# ==========================================
# 1. DEFINISI SEMUA LAYAR (SCREEN)
# ==========================================

class SystemMonitorScreen(Screen):
    """Dashboard utama menampilkan metrics sistem."""
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("t", "to_tasks", "Tasks"),
        Binding("l", "to_logs", "Logs"),
        Binding("s", "to_settings", "Settings"),
    ]

    cpu_usage = reactive(0.0)
    ram_usage = reactive(0.0)
    disk_io = reactive(0.0)
    network_rx = reactive(0)
    network_tx = reactive(0)

    def compose(self) -> ComposeResult:
        yield Header()
        
        with Container(id="dashboard-container"):
            with Vertical(id="stat-card"):
                yield Label("[bold cyan]CPU USAGE[/]", id="cpu-label")
                yield Static("", id="cpu-bar")
                yield Label("[bold magenta]RAM USAGE[/]", id="ram-label")
                yield Static("", id="ram-bar")
                yield Label("[bold yellow]NETWORK[/]", id="net-label")
                yield Static("", id="net-stat")
                yield Label("[bold green]DISK[/]", id="disk-label")
                yield Static("", id="disk-stat")

        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(1.0, self.update_metrics)

    def update_metrics(self):
        self.cpu_usage = max(0.0, min(100.0, self.cpu_usage + random.uniform(-5.0, 5.0)))
        self.ram_usage = max(10.0, min(95.0, self.ram_usage + random.uniform(-2.0, 2.0)))
        self.disk_io = abs(random.gauss(50, 10))
        self.network_rx = int(random.gauss(1500, 300))
        self.network_tx = int(random.gauss(800, 150))
        
        self.refresh_ui()

    def refresh_ui(self):
        try:
            cpu_bar_len = int(self.cpu_usage / 2)
            cpu_color = "red" if self.cpu_usage > 80 else "blue" if self.cpu_usage > 50 else "green"
            self.query_one("#cpu-bar", Static).update(f"[{cpu_color}]{self.cpu_usage:.1f}% {'█' * cpu_bar_len}[/]")
            
            ram_bar_len = int(self.ram_usage / 2)
            ram_color = "red" if self.ram_usage > 80 else "yellow" if self.ram_usage > 50 else "green"
            self.query_one("#ram-bar", Static).update(f"[{ram_color}]{self.ram_usage:.1f}% {'█' * ram_bar_len}[/]")

            self.query_one("#net-stat", Static).update(
                f"RX: {self.network_rx} KB/s | TX: {self.network_tx} KB/s"
            )
            self.query_one("#disk-stat", Static).update(
                f"Read: {self.disk_io:.1f} MB/s | Write: {self.disk_io * 0.8:.1f} MB/s"
            )
        except Exception:
            pass 

    def action_to_tasks(self):
        self.app.push_screen(TasksScreen())

    def action_to_logs(self):
        self.app.push_screen(LogsScreen())

    def action_to_settings(self):
        self.app.push_screen(SettingsScreen())


class TasksScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "go_back", "Back"),
        Binding("a", "add_task", "Add Task"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(cursor_type="row", id="task-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#task-table", DataTable)
        table.add_columns("PID", "Name", "Status")
        
        processes = [
            ("1001", "nginx", "Running"),
            ("1042", "python", "Running"),
            ("2099", "postgres", "Sleeping"),
        ]
        for p in processes:
            table.add_row(*p)

    def action_add_task(self):
        table = self.query_one("#task-table", DataTable)
        pid = random.randint(4000, 9999)
        status = random.choice(["Running", "Sleeping"])
        table.add_row(str(pid), f"proc-{pid}", status)
        self.notify(f"New process: {pid}")

    def action_go_back(self):
        self.app.pop_screen()


class LogsScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        # PERBAIKAN: Menghapus parameter markup=True
        yield Log(id="log-viewer") 
        yield Footer()

    def on_mount(self) -> None:
        self.log_viewer = self.query_one("#log-viewer", Log)
        self.run_worker(self.stream_logs)

    async def stream_logs(self):
        messages = [
            "[INFO] Server started",
            "[WARN] High latency",
            "[ERROR] Auth failed",
            "[INFO] Backup completed",
        ]
        
        while True:
            msg = random.choice(messages)
            timestamp = datetime.now().strftime("%H:%M:%S")
            try:
                # Karena markup dihapus, kita tidak bisa pakai warna di dalam Log
                self.log_viewer.write(f"[{timestamp}] {msg}")
            except Exception:
                break 
            await asyncio.sleep(random.uniform(0.5, 2.0))

    def action_go_back(self):
        self.app.pop_screen()


class SettingsScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="settings-container"):
            yield Label("[bold]Configuration[/]")
            yield Button("Apply Changes", id="btn-apply")
            yield Button("Reset Defaults", id="btn-reset")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-apply":
            self.notify("Applied successfully.")
        elif event.button.id == "btn-reset":
            self.notify("Reset to defaults.")

    def action_go_back(self):
        self.app.pop_screen()


# ==========================================
# 2. MAIN APLIKASI
# ==========================================

class DashboardApp(App):
    
    CSS = """
    Screen {
        background: $surface;
    }

    #dashboard-container {
        height: 100%;
        width: 100%;
        padding: 1;
    }

    #stat-card {
        height: auto;
        border: round blue;
        padding: 1 2;
        margin-bottom: 1;
    }

    #cpu-bar, #ram-bar, #net-stat, #disk-stat {
        height: 1;
        background: $surface;
        color: $text;
        margin-bottom: 1;
    }

    DataTable {
        height: 100%;
    }

    Log {
        height: 100%;
        border: solid green;
    }

    #settings-container {
        width: 80%;
        height: auto;
        border: round white;
        padding: 1;
    }
    
    Button {
        width: 100%;
        margin-bottom: 1;
    }
    """

    def on_mount(self) -> None:
        self.push_screen(SystemMonitorScreen())

if __name__ == "__main__":
    app = DashboardApp()
    app.run()
