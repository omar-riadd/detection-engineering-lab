"""
Background file watcher using Python's watchdog library.
Monitors rules/sigma/**/*.yml for changes and re-syncs to SQLite,
then broadcasts 'rule_changed' events to all connected WebSocket clients.
"""
import asyncio
import threading
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from api.core.reconciler import delete_sigma_rule, sync_sigma_rule
from api.models.db import engine
from sqlalchemy.orm import Session


class SigmaRuleHandler(FileSystemEventHandler):
    """
    Watchdog event handler for Sigma YAML file changes.
    Runs in a background thread; posts async tasks to the event loop.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, broadcast_fn):
        super().__init__()
        self._loop = loop
        self._broadcast = broadcast_fn
        self._debounce_timers: dict[str, threading.Timer] = {}
        self._debounce_delay = 0.3  # 300ms debounce

    def _debounced_handle(self, event: FileSystemEvent):
        """Cancel any pending timer for this path, schedule a new one."""
        path = event.src_path
        if path in self._debounce_timers:
            self._debounce_timers[path].cancel()

        timer = threading.Timer(
            self._debounce_delay,
            self._handle_sync,
            args=(event,),
        )
        self._debounce_timers[path] = timer
        timer.start()

    def _handle_sync(self, event: FileSystemEvent):
        """Perform the actual sync in background thread after debounce."""
        path = Path(event.src_path)
        if path.suffix not in (".yml", ".yaml"):
            return

        result = None
        with Session(engine) as session:
            if event.event_type == "deleted":
                result = delete_sigma_rule(path, session)
            else:
                result = sync_sigma_rule(path, session)

        if result:
            # Schedule broadcast on the async event loop
            asyncio.run_coroutine_threadsafe(
                self._broadcast({"event": "rule_changed", "data": result}),
                self._loop,
            )

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._debounced_handle(event)

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._debounced_handle(event)

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self._debounced_handle(event)

    def on_moved(self, event):
        if not event.is_directory:
            # Treat move as delete old + create new
            path_old = Path(event.src_path)
            path_new = Path(event.dest_path)
            with Session(engine) as session:
                if path_old.suffix in (".yml", ".yaml"):
                    delete_sigma_rule(path_old, session)
                if path_new.suffix in (".yml", ".yaml"):
                    sync_sigma_rule(path_new, session)


class FileWatcher:
    """
    Manages the watchdog Observer lifecycle.
    Started during FastAPI lifespan; stopped on shutdown.
    """

    def __init__(self, watch_dir: Path, broadcast_fn):
        self._watch_dir = watch_dir
        self._broadcast_fn = broadcast_fn
        self._observer: Observer | None = None

    def start(self, loop: asyncio.AbstractEventLoop):
        handler = SigmaRuleHandler(loop, self._broadcast_fn)
        self._observer = Observer()
        self._observer.schedule(handler, str(self._watch_dir), recursive=True)
        self._observer.start()
        print(f"[WATCHER] Monitoring {self._watch_dir} for rule changes")

    def stop(self):
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join()
            print("[WATCHER] Stopped")
