# ADR 0002: Async Subprocess Streaming over WebSockets for Continuous Test Telemetry

## Status
Accepted

## Context
A hallmark of Detection-as-Code is automated regression verification: every detection rule must be verified against positive attack fixtures and benign baseline traffic. When executing test runs (`pytest tests/`) or log replay engines (`scripts/replay_logs.py`), developers and SOC engineers need immediate, real-time feedback without waiting for batch completion or polling HTTP endpoints.

## Decision
We implemented real-time asynchronous subprocess execution and terminal streaming using Python's `asyncio.create_subprocess_exec` and WebSockets:
1. **Unbuffered Stdout**: Subprocesses are spawned with `PYTHONUNBUFFERED=1` and `-u` flags to prevent buffering delays in the stdout pipe.
2. **Line-by-Line Streaming**: Stdout/stderr streams are read asynchronously (`proc.stdout.readline()`) and pushed immediately to connected WebSocket clients as JSON packets (`{"type": "stdout", "data": line}`).
3. **Graceful Cancellation**: Client disconnects (`WebSocketDisconnect`) trigger graceful process termination (`proc.terminate()`) followed by SIGKILL if unresponsive, preventing orphan child processes.
4. **Telemetry Persistence**: Upon process exit, execution metrics (exit code, duration, output tail, rule ID, run type) are persisted to the `test_runs` SQLite table and exposed via `GET /api/test-runs`.

This design pattern directly mirrors production CI/CD log streaming engines found in GitHub Actions runners, GitLab CI, and Kubernetes pod log tails.

## Consequences
- **Positive**: Sub-millisecond latency for live terminal feedback in the web browser.
- **Positive**: Zero polling load on the server.
- **Positive**: Historical test metrics and latency trends are preserved for SOC auditing and CV demonstration.
