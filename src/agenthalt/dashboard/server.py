"""AgentHalt Real-Time Dashboard — Flask + SocketIO server.

Provides a live monitoring dashboard showing:
- Real-time guard evaluations as they happen
- Budget spend tracking with visual gauges
- Rate limit and loop detection alerts
- Approval request queue
- Audit log with filtering
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("agenthalt.dashboard")

# Track events for the dashboard
_event_buffer: list[dict[str, Any]] = []
_event_buffer_max = 1000
_stats: dict[str, Any] = {
    "total_evaluations": 0,
    "total_allowed": 0,
    "total_denied": 0,
    "total_approvals": 0,
    "start_time": time.time(),
}
_socketio: Any = None


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

        # Broadcast to all connected SocketIO clients
        if _socketio is not None:
            _socketio.emit("event", event)

    return listener


def create_app(engine: Any = None) -> Any:
    """Create the Flask + SocketIO dashboard application."""
    global _socketio

    try:
        from flask import Flask, jsonify
        from flask_socketio import SocketIO
    except ImportError as err:
        raise ImportError(
            "Dashboard requires Flask and Flask-SocketIO. "
            "Install with: pip install flask flask-socketio"
        ) from err

    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["SECRET_KEY"] = "agenthalt-dashboard"

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
    _socketio = socketio

    if engine is not None:
        engine.add_event_listener(create_event_listener())

    @app.route("/")
    def index():
        html_path = Path(__file__).parent / "templates" / "dashboard.html"
        return html_path.read_text()

    @app.route("/api/stats")
    def get_stats():
        uptime = time.time() - _stats["start_time"]
        return jsonify(
            {**_stats, "uptime_seconds": uptime, "buffer_size": len(_event_buffer)}
        )

    @app.route("/api/events")
    def get_events():
        return jsonify(_event_buffer[-50:])

    @socketio.on("connect")
    def on_connect():
        logger.info("Dashboard client connected")
        # Send initial stats + recent events on connect
        socketio.emit("stats", _stats)
        for event in _event_buffer[-50:]:
            socketio.emit("event", event)

    @socketio.on("ping")
    def on_ping():
        socketio.emit("pong", {"timestamp": time.time()})

    return app, socketio


def run_dashboard(
    engine: Any = None, host: str = "127.0.0.1", port: int = 8550
) -> None:
    """Start the dashboard server (blocking)."""
    try:
        from flask_socketio import SocketIO  # noqa: F401
    except ImportError as err:
        raise ImportError(
            "Dashboard requires flask-socketio. Install with: pip install flask flask-socketio"
        ) from err

    app, socketio = create_app(engine)
    print(f"\n🛡️  AgentHalt Dashboard: http://{host}:{port}\n")
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
