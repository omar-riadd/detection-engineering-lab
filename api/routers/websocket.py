"""
WebSocket endpoints:
  /ws/events       — broadcast channel for rule_changed events (file watcher)
  /ws/test-runner  — bidirectional: receive run commands, stream pytest output
  /ws/replay       — stream replay_logs.py output for a specific rule
"""
import asyncio
import os
import sys
from pathlib import Path

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.core.ws_manager import ws_manager

PROJECT_ROOT = Path(__file__).parent.parent.parent

router = APIRouter(tags=["websocket"])


# ──────────────────────────────────────────────────────────────────────────────
# /ws/events — Live rule-change broadcast channel
# ──────────────────────────────────────────────────────────────────────────────
@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    Persistent event stream. Clients connect and receive push notifications when:
    - A Sigma YAML file is modified/added/deleted on disk (file watcher)
    - A test run completes
    The client never sends commands here; use /ws/test-runner for that.
    """
    await ws_manager.connect(websocket)
    try:
        # Send initial connection ack
        await websocket.send_json({"event": "connected", "data": {"active_clients": ws_manager.active_count}})
        # Keep alive — just wait for disconnect
        while True:
            try:
                # Receive (and discard) any ping from client to keep connection alive
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send keepalive ping
                await websocket.send_json({"event": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(websocket)


import time
from datetime import datetime, timezone
from api.models.db import TestRun, Rule, engine
from sqlalchemy.orm import Session

def _resolve_pytest_filter(rule_id: str | None) -> str | None:
    """
    Resolves a rule UUID or identifier to a pytest -k filter expression.
    Matches against rule file stem and/or MITRE ATT&CK technique IDs.
    """
    if not rule_id:
        return None
    try:
        with Session(engine) as session:
            rule_obj = session.get(Rule, rule_id)
            if rule_obj:
                terms = []
                if rule_obj.file_path:
                    terms.append(Path(rule_obj.file_path).stem)
                if rule_obj.techniques:
                    for t in rule_obj.techniques.split("|"):
                        clean_t = t.strip()
                        if clean_t:
                            terms.append(clean_t)
                if terms:
                    return " or ".join(terms)
    except Exception as e:
        print(f"[RESOLVE_PYTEST_FILTER_ERROR] {e}")
    return rule_id

def _record_test_run(run_type: str, rule_id: str | None, exit_code: int, duration: float, output_text: str) -> int:
    try:
        with Session(engine) as session:
            status = "pass" if exit_code == 0 else "fail"
            tr = TestRun(
                rule_id=rule_id,
                run_type=run_type,
                status=status,
                exit_code=exit_code,
                duration_seconds=round(duration, 3),
                output=output_text[-4000:] if output_text else "",
                finished_at=datetime.now(timezone.utc),
            )
            session.add(tr)
            session.commit()
            return tr.id
    except Exception as e:
        print(f"[TEST_RUN_RECORD_ERROR] {e}")
        return 0


# ──────────────────────────────────────────────────────────────────────────────
# Subprocess streaming helper
# ──────────────────────────────────────────────────────────────────────────────
async def _stream_subprocess(
    cmd: list[str],
    websocket: WebSocket,
    run_type: str = "pytest",
    rule_id: str | None = None,
):
    """
    Execute a subprocess and stream stdout/stderr line-by-line over WebSocket.
    Persists test telemetry to the SQLite test_runs table on completion.
    Handles client disconnect cleanly (terminates subprocess).
    """
    start_time = time.time()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
        cwd=str(PROJECT_ROOT),
    )

    await websocket.send_json({"type": "started", "pid": proc.pid})

    captured_lines: list[str] = []
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip("\n")
            captured_lines.append(text)
            await websocket.send_json({"type": "stdout", "data": text})

        exit_code = await proc.wait()
        duration = time.time() - start_time

        # Persist to database read model
        test_run_id = await asyncio.to_thread(
            _record_test_run,
            run_type,
            rule_id,
            exit_code,
            duration,
            "\n".join(captured_lines),
        )

        await websocket.send_json({
            "type": "exit",
            "code": exit_code,
            "run_id": test_run_id,
            "duration": round(duration, 2),
        })
        return exit_code

    except (WebSocketDisconnect, Exception):
        # Client disconnected — kill orphan subprocess
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                proc.kill()
        raise



# ──────────────────────────────────────────────────────────────────────────────
# /ws/test-runner — Live pytest streaming
# ──────────────────────────────────────────────────────────────────────────────
@router.websocket("/ws/test-runner")
async def websocket_test_runner(websocket: WebSocket):
    """
    Bidirectional WebSocket for running pytest with live output streaming.

    Client sends:  {"action": "run_tests", "rule_id": "win_proc_access_lsass_memory"}
                   {"action": "run_all"}
    Server sends:  {"type": "started"|"stdout"|"exit", ...}

    CV talking point: async subprocess streaming identical to CI/CD log streaming
    in platforms like GitHub Actions or Argo CD rollout monitoring.
    """
    await websocket.accept()
    try:
        while True:
            message = await websocket.receive_json()
            action = message.get("action", "")
            rule_id = message.get("rule_id")

            python_exe = sys.executable

            if action == "run_all":
                cmd = [python_exe, "-u", "-m", "pytest", "tests/", "-v", "--no-header", "--tb=short"]
            elif action == "run_tests" and rule_id:
                filter_expr = _resolve_pytest_filter(rule_id)
                cmd = [python_exe, "-u", "-m", "pytest", "tests/", "-v", "--no-header", "--tb=short",
                       "-k", filter_expr]
            else:
                await websocket.send_json({"type": "error", "data": f"Unknown action: {action}"})
                continue

            await websocket.send_json({"type": "status", "data": f"$ {' '.join(cmd)}"})
            try:
                await _stream_subprocess(
                    cmd,
                    websocket,
                    run_type="pytest",
                    rule_id=rule_id if action == "run_tests" else None,
                )
            except WebSocketDisconnect:

                return

    except WebSocketDisconnect:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# /ws/replay — Live replay_logs.py streaming for a specific rule or all
# ──────────────────────────────────────────────────────────────────────────────
@router.websocket("/ws/replay")
async def websocket_replay(websocket: WebSocket):
    """
    Stream output from scripts/replay_logs.py in real-time.

    Client sends:  {"action": "replay", "rule_id": "win_proc_access_lsass_memory"}
                   {"action": "replay_all"}
    """
    await websocket.accept()
    try:
        while True:
            message = await websocket.receive_json()
            action = message.get("action", "")
            rule_id = message.get("rule_id")
            python_exe = sys.executable

            if action == "replay_all":
                # --type all --verbose: replay every fixture against every rule
                cmd = [python_exe, "-u", "scripts/replay_logs.py", "--type", "all", "--verbose"]
            elif action == "replay" and rule_id:
                # replay_logs.py supports --rule with UUID, stem name, or technique
                cmd = [python_exe, "-u", "scripts/replay_logs.py", "--type", "all", "--verbose",
                       "--rule", rule_id]
            else:
                await websocket.send_json({"type": "error", "data": f"Unknown action: {action}"})
                continue

            await websocket.send_json({"type": "status", "data": f"$ {' '.join(cmd)}"})
            try:
                await _stream_subprocess(
                    cmd,
                    websocket,
                    run_type="replay",
                    rule_id=rule_id if action == "replay" else None,
                )
            except WebSocketDisconnect:

                return

    except WebSocketDisconnect:
        pass
