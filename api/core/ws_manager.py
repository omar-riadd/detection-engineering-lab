"""
WebSocket connection manager.
Tracks all active browser connections and broadcasts events.
Used for: rule_changed events (file watcher), test run output streaming.
"""
import asyncio
import json
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self):
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)

    async def broadcast(self, data: Any):
        """Broadcast JSON-serializable data to all connected clients."""
        message = json.dumps(data)
        dead = []
        async with self._lock:
            connections = list(self._connections)
        for ws in connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        # Clean up dead connections
        if dead:
            async with self._lock:
                for ws in dead:
                    if ws in self._connections:
                        self._connections.remove(ws)

    @property
    def active_count(self) -> int:
        return len(self._connections)


# Global instance — shared across all routers
ws_manager = ConnectionManager()
