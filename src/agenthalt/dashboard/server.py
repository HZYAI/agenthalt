"""AgentHalt Real-Time Dashboard — FastAPI + WebSocket server.

Provides a live monitoring dashboard showing:
- Real-time guard evaluations as they happen
- Budget spend tracking with visual gauges
- Rate limit and loop detection alerts
- Approval request queue
- Audit log with filtering
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("agenthalt.dashboard")

# Track events for the dashboard
_event_buffer: list[dict[str, Any]] = []
_event_buffer_max = 1000
_connected_clients: set[Any] = set()
_stats: dict[str, Any] = {
    "total_evaluations": 0,
    "total_allowed": 0,
    "total_denied": 0,
    "total_approvals": 0,
    "start_time": time.time(),
}


def create_event_listener():
    """Create an event listener function for PolicyEngine.add_event_listener()."""

    def listener(event: dict[str, Any]) -> None:
        global _event_buffer
        _event_buffer.append(event)
        if len(_event_buffer) > _event_buffer_max:
            _event_buffer = _event_buffer[-_event_buffer_max:]

        # Update stats
        if event.get("type") == "evaluation":
            _stats["total_evaluations"] += 1
            decision = event.get("decision", "")
            if decision == "allow":
                _stats["total_allowed"] += 1
            elif decision == "deny":
                _stats["total_denied"] += 1
            elif decision == "require_approval":
                _stats["total_approvals"] += 1

        # Broadcast to WebSocket clients
        for client in list(_connected_clients):
            try:
                asyncio.ensure_future(client.send_json(event))
            except Exception:
                _connected_clients.discard(client)

    return listener


def create_app(engine: Any = None) -> Any:
    """Create the FastAPI dashboard application.

    Args:
        engine: Optional PolicyEngine instance to monitor.
    """
    try:
        from fastapi import FastAPI, WebSocket, WebSocketDisconnect
        from fastapi.responses import HTMLResponse
    except ImportError as err:
        raise ImportError(
            "Dashboard requires FastAPI. Install with: pip install agenthalt[dashboard]"
        ) from err

    app = FastAPI(title="AgentHalt Dashboard", version="0.1.0")

    if engine is not None:
        engine.add_event_listener(create_event_listener())

    @app.get("/", response_class=HTMLResponse)
    async def index():
        html_path = Path(__file__).parent / "templates" / "dashboard.html"
        return HTMLResponse(html_path.read_text())

    @app.get("/api/stats")
    async def get_stats():
        uptime = time.time() - _stats["start_time"]
        return {
            **_stats,
            "uptime_seconds": uptime,
            "connected_clients": len(_connected_clients),
            "buffer_size": len(_event_buffer),
        }

    @app.get("/api/events")
    async def get_events(limit: int = 50):
        return _event_buffer[-limit:]

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        _connected_clients.add(websocket)
        logger.info("Dashboard client connected (%d total)", len(_connected_clients))
        try:
            # Send initial stats
            await websocket.send_json({"type": "stats", **_stats})
            # Send recent events
            for event in _event_buffer[-20:]:
                await websocket.send_json(event)
            # Keep alive
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug("WebSocket error: %s", e)
        finally:
            _connected_clients.discard(websocket)
            logger.info("Dashboard client disconnected (%d remaining)", len(_connected_clients))

    return app


def run_dashboard(engine: Any = None, host: str = "127.0.0.1", port: int = 8550) -> None:
    """Start the dashboard server (blocking).

    Usage:
        from agenthalt.dashboard.server import run_dashboard
        run_dashboard(engine, port=8550)
    """
    try:
        import uvicorn
    except ImportError as err:
        raise ImportError(
            "Dashboard requires uvicorn. Install with: pip install agenthalt[dashboard]"
        ) from err

    app = create_app(engine)
    print(f"\n🛡️  AgentHalt Dashboard: http://{host}:{port}\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")
