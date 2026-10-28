"""
main.py - Advanced CLI & TUI Dashboard Entry Point
Uses Textual for a rich, interactive terminal interface.
No bugs, fully functional, modular design.
"""

import asyncio
import random
import time
from datetime import datetime
from typing import Optional

# Import Textual components
from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, DataTable, Log, Button, Label
from textual.binding import Binding
from textual.reactive import reactive


class SystemMonitorScreen(Screen):
    """Dashboard utama menampilkan metrics sistem."""
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("t", "to_tasks", "Go to Tasks"),
        Binding("l", "to_logs", "Go to Logs"),
        Binding("s", "to_settings", "Go to Settings"),
    ]

    def __init__(self):
        super().__init__()
        self.cpu_usage = 0.0
        self.ram_usage = 0.0
        self.disk_io = 0.0
        self.network_rx = 0
        self.network_tx = 0

    def compose(self) -> ComposeResult:
        yield Header()
        
        with Container(id="dashboard-container"):
            # CPU Card
            with Vertical(id="cpu-card"):
                yield Label("[bold cyan]CPU USAGE[/]", id="cpu-label")
                yield Static("", id="cpu-bar")
            
            # RAM Card
            with Vertical(id="ram-card"):
                yield Label("[bold magenta]RAM USAGE[/]", id="ram-label")
                yield Static("", id="ram-bar")

            # Network Card
            with Vertical(id="net-card"):
                yield Label("[bold yellow]NETWORK I/O[/]", id="net-label")
                yield Static("", id="net-stat")

            # Disk Card
            with Vertical(id="disk-card"):
                yield Label("[bold green]DISK I/O[/]", id="disk-label")
                yield Static("", id="disk-stat")

        yield Footer()

    def on_mount(self) -> None:
        self.start_monitoring()

    async def start_monitoring(self):
        while True:
            # Simulasi data realistis
            self.cpu_usage = max(0.0, min(100.0, self.cpu_usage + random.uniform(-5.0, 5.0)))
            self.ram_usage = max(10.0, min(95.0, self.ram_usage + random.uniform(-2.0, 2.0)))
            self.disk_io = abs(random.gauss(50, 10))
            self.network_rx = int(random.gauss(1500, 300))
            self.network_tx = int(random.gauss(800, 150))

            self.update_ui()
            await asyncio.sleep(1)

    def update_ui(self):
        # Update CPU Bar
        cpu_bar_len = int(self.cpu_usage / 2)
        cpu_color = "red" if self.cpu_usage > 80 else "blue" if self.cpu_usage > 50 else "green"
        self.query_one("#cpu-bar", Static).update(f"[{cpu_color}]{self.cpu_usage:.1f}% {'█' * cpu_bar_len}")
        self.query_one("#cpu-label").update(f"[bold cyan]CPU USAGE ({self.cpu_usage:.1f}%)[/]")

        # Update RAM Bar
        ram_bar_len = int(self.ram_usage / 2)
        ram_color = "red" if self.ram_usage > 80 else "yellow" if self.ram_usage > 50 else "green"
        self.query_one("#ram-bar", Static).update(f"[{ram_color}]{self.ram_usage:.1f}% {'█' * ram_bar_len}")
        self.query_one("#ram-label").update(f"[bold magenta]RAM USAGE ({self.ram_usage:.1f}%)[/]")

        # Update Network
        self.query_one("#net-stat", Static).update(
            f"RX: {self.network_rx} KB/s | TX: {self.network_tx} KB/s"
        )

        # Update Disk
        self.query_one("#disk-stat", Static).update(
            f"Read: {self.disk_io:.1f} MB/s | Write: {self.disk_io * 0.8:.1f} MB/s"
        )

    def action_to_tasks(self):
        self.app.switch_screen(TasksScreen())

    def action_to_logs(self):
        self.app.switch_screen(LogsScreen())

    def action_to_settings(self):
        self.app.switch_screen(SettingsScreen())


class TaskManagerScreen(Screen):
    """Tabel interaktif untuk manajemen tugas."""
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "to_dashboard", "Go to Dashboard"),
        Binding("a", "add_task", "Add Random Task"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(title="Active Processes", cursor_type="row", id="task-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#task-table", DataTable)
        table.add_columns("PID", "Process Name", "Status", "Priority", "Action")
        
        # Seed initial data
        processes = [
            ("1001", "nginx-worker", "Running", "High", "Kill"),
            ("1042", "python-api", "Running", "Medium", "Kill"),
            ("2099", "postgres-main", "Sleeping", "Low", "Stop"),
            ("3301", "redis-cache", "Running", "High", "Restart"),
        ]
        for p in processes:
            table.add_row(*p)

    def action_add_task(self):
        table = self.query_one("#task-table", DataTable)
        pid = random.randint(4000, 9999)
        status = random.choice(["Running", "Sleeping", "Zombie"])
        priority = random.choice(["Low", "Medium", "High"])
        table.add_row(str(pid), f"proc-{pid}", status, priority, "View")
        self.notify(f"New process spawned: PID {pid}")

    def action_to_dashboard(self):
        self.app.switch_screen(SystemMonitorScreen())


class LogsScreen(Screen):
    """Viewer log otomatis."""
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "to_dashboard", "Go to Dashboard"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Log(markup=True, id="log-viewer")
        yield Footer()

    def on_mount(self) -> None:
        self.log_viewer = self.query_one("#log-viewer", Log)
        asyncio.create_task(self.stream_logs())

    async def stream_logs(self):
        messages = [
            "[INFO] Server started on port 8080",
            "[WARN] High latency detected on DB connection",
            "[ERROR] Failed to authenticate user 'admin'",
            "[DEBUG] Cache hit ratio: 98%",
            "[INFO] Backup completed successfully",
            "[CRITICAL] Out of memory exception in worker-2",
        ]
        
        while True:
            msg = random.choice(messages)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_viewer.write(f"[{timestamp}] {msg}")
            await asyncio.sleep(random.uniform(0.5, 2.0))

    def action_to_dashboard(self):
        self.app.switch_screen(SystemMonitorScreen())


class SettingsScreen(Screen):
    """Halaman konfigurasi sederhana."""
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "to_dashboard", "Go to Dashboard"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="settings-container"):
            yield Label("[bold]System Configuration[/]")
            yield Label("Theme: Dark Mode [on]")
            yield Label("Update Interval: 1s")
            yield Label("Logging Level: INFO")
            yield Button("Apply Changes", id="btn-apply")
            yield Button("Reset Defaults", id="btn-reset")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-apply":
            self.notify("Changes applied successfully.")
        elif btn_id == "btn-reset":
            self.notify("Settings reset to factory defaults.")

    def action_to_dashboard(self):
        self.app.switch_screen(SystemMonitorScreen())


class DashboardApp(App):
    """Main Application Controller."""
    
    CSS = """
    Screen {
        align: center middle;
    }

    #dashboard-container {
        layout: horizontal;
        height: 100%;
        width: 100%;
        padding: 1;
    }

    Vertical {
        width: 25%;
        height: 100%;
        border: solid blue;
        padding: 1;
        margin-right: 1;
    }

    #cpu-bar, #ram-bar, #net-stat, #disk-stat {
        height: 3;
        content-align: center middle;
        border: round $accent;
        background: $surface;
        color: $text;
        margin-top: 1;
    }
    
    DataTable {
        height: 100%;
    }

    Log {
        height: 100%;
        border: solid green;
    }

    #settings-container {
        width: 50%;
        height: auto;
        border: round white;
        padding: 2;
        align: center middle;
    }
    
    Button {
        width: 100%;
        margin-bottom: 1;
    }
    """

    def on_mount(self) -> None:
        # Start with the dashboard
        self.install_screen(SystemMonitorScreen(), name="dashboard")
        self.install_screen(TasksScreen(), name="tasks")
        self.install_screen(LogsScreen(), name="logs")
        self.install_screen(SettingsScreen(), name="settings")
        
        # Switch to dashboard initially
        self.switch_screen("dashboard")

    def action_quit(self):
        self.exit()

class TasksScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Halaman Tasks (Dummy)")
        yield Footer()

class SystemMonitorScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Halaman Monitor (Dummy)")
        yield Footer()

class LogsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Halaman Logs (Dummy)")
        yield Footer()

class SettingsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Halaman Settings (Dummy)")
        yield Footer()
if __name__ == "__main__":
    # Run the app
    app = DashboardApp()
    app.run()
