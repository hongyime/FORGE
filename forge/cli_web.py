"""Web and distributed-worker command registration for the Forge CLI."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
from typing import Optional

import typer
from rich.console import Console

from forge.config import ForgeConfig


def register_web_commands(web_app: typer.Typer, *, console: Console) -> None:
    """Register web UI and distributed-worker commands on the web sub-app."""

    @web_app.command("start")
    def web_start(
        host: Optional[str] = typer.Option(None, "--host"),
        port: Optional[int] = typer.Option(None, "--port"),
        daemon: bool = typer.Option(False, "--daemon"),
    ) -> None:
        cfg = ForgeConfig.load()
        web_host = host or cfg.web_host
        web_port = port or cfg.web_port
        if daemon:
            cmd = [
                sys.executable,
                "-m",
                "uvicorn",
                "forge.webui.app:create_app",
                "--factory",
                "--host",
                web_host,
                "--port",
                str(web_port),
            ]
            proc = subprocess.Popen(cmd)
            pid_file = cfg.data_dir / "webui.pid"
            pid_file.write_text(str(proc.pid), encoding="utf-8")
            console.print(f"[green]Web interface started in background (PID {proc.pid}).[/green]")
            console.print(f"[green]URL:[/green] http://{web_host}:{web_port}")
            return
        from forge.webui.app import create_server  # noqa: PLC0415

        console.print(f"[green]Starting web interface on http://{web_host}:{web_port}[/green]")
        server = create_server(host=web_host, port=web_port)
        server.run()

    @web_app.command("stop")
    def web_stop() -> None:
        cfg = ForgeConfig.load()
        pid_file = cfg.data_dir / "webui.pid"
        if not pid_file.exists():
            console.print("[yellow]No running web interface PID file found.[/yellow]")
            raise typer.Exit(code=0)
        pid_raw = pid_file.read_text(encoding="utf-8").strip()
        if not pid_raw.isdigit():
            pid_file.unlink(missing_ok=True)
            console.print("[yellow]Invalid PID file removed.[/yellow]")
            raise typer.Exit(code=1)
        pid = int(pid_raw)
        try:
            os.kill(pid, signal.SIGTERM)
            console.print(f"[green]Stopped web interface process {pid}.[/green]")
        except Exception as exc:
            console.print(f"[bold red]ERROR:[/bold red] Could not stop process {pid}: {exc}")
            raise typer.Exit(code=1)
        finally:
            pid_file.unlink(missing_ok=True)

    @web_app.command("status")
    def web_status(
        host: Optional[str] = typer.Option(None, "--host"),
        port: Optional[int] = typer.Option(None, "--port"),
    ) -> None:
        cfg = ForgeConfig.load()
        web_host = host or cfg.web_host
        web_port = port or cfg.web_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            connected = sock.connect_ex((web_host, web_port)) == 0
        finally:
            sock.close()
        if connected:
            console.print(f"[green]Web interface is running at http://{web_host}:{web_port}[/green]")
        else:
            console.print(
                f"[yellow]Web interface is not listening at {web_host}:{web_port}[/yellow]"
            )

    @web_app.command("enqueue")
    def web_enqueue(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        task_type: str = typer.Option(..., "--task-type"),
        target: Optional[str] = typer.Option(None, "--target"),
        priority: int = typer.Option(100, "--priority"),
    ) -> None:
        from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415
        from forge.distributed.scheduler import ScheduledTask, TaskScheduler  # noqa: PLC0415

        cfg = ForgeConfig.load()
        coordinator = QueueCoordinator(redis_url=cfg.redis_url)
        scheduler = TaskScheduler(db_path=cfg.engagement_db_path(engagement), queue=coordinator)
        payload = {"task_type": task_type.strip().lower(), "target": (target or "").strip()}
        task_key = f"{payload['task_type']}:{payload['target'] or 'default'}"
        scheduler.schedule(
            ScheduledTask(
                engagement_id=int(engagement),
                task_key=task_key,
                payload=payload,
                priority=priority,
            )
        )
        console.print(f"[green]Task queued:[/green] {task_key}")

    @web_app.command("worker-once")
    def web_worker_once(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        worker_id: str = typer.Option("worker-1", "--worker-id"),
    ) -> None:
        from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415
        from forge.distributed.runnable import ScheduledTaskRunner  # noqa: PLC0415
        from forge.distributed.scheduler import TaskScheduler  # noqa: PLC0415
        from forge.distributed.worker import Worker  # noqa: PLC0415

        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(engagement)
        coordinator = QueueCoordinator(redis_url=cfg.redis_url)
        scheduler = TaskScheduler(db_path=db_path, queue=coordinator)
        worker = Worker(
            worker_id=worker_id,
            queue=coordinator,
            scheduler=scheduler,
            handler=ScheduledTaskRunner(db_path),
            handler_execution_mode="process",
        )
        consumed = worker.run_once()
        if consumed:
            console.print("[green]Worker executed one queued task.[/green]")
        else:
            console.print("[yellow]No queued tasks available.[/yellow]")

    @web_app.command("worker-loop")
    def web_worker_loop(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        worker_id: str = typer.Option("worker-1", "--worker-id"),
        idle_sleep: float = typer.Option(0.5, "--idle-sleep"),
    ) -> None:
        from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415
        from forge.distributed.runnable import ScheduledTaskRunner  # noqa: PLC0415
        from forge.distributed.scheduler import TaskScheduler  # noqa: PLC0415
        from forge.distributed.worker import Worker  # noqa: PLC0415

        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(engagement)
        coordinator = QueueCoordinator(redis_url=cfg.redis_url)
        scheduler = TaskScheduler(db_path=db_path, queue=coordinator)
        worker = Worker(
            worker_id=worker_id,
            queue=coordinator,
            scheduler=scheduler,
            handler=ScheduledTaskRunner(db_path),
            handler_execution_mode="process",
        )
        console.print(f"[green]Worker loop started:[/green] {worker_id}")
        worker.run_forever(idle_sleep_seconds=idle_sleep)

    @web_app.command("automation-loop")
    def web_automation_loop(
        engagement: str = typer.Option(..., "--engagement", "-e"),
    ) -> None:
        from forge.distributed.coordinator import QueueCoordinator  # noqa: PLC0415
        from forge.distributed.scheduler import TaskScheduler  # noqa: PLC0415
        from forge.utils.automation import AutomationEngine  # noqa: PLC0415

        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(engagement)
        coordinator = QueueCoordinator(redis_url=cfg.redis_url)
        scheduler = TaskScheduler(db_path=db_path, queue=coordinator)

        engine = AutomationEngine(
            engagement_id=int(engagement), queue=coordinator, scheduler=scheduler
        )
        console.print(f"[green]Automation Engine loop started for engagement:[/green] {engagement}")
        engine.run_event_loop()
