#!/usr/bin/env python3
# AISTVM Linux terminal agent. Standard library only.
# Serves command execution and resource metrics over the Tailscale interface.
import hmac
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("AISTVM_TERMINAL_PORT", "8790"))
TOKEN = os.environ.get("AISTVM_TERMINAL_TOKEN", "")
LINUX_USER = os.environ.get("AISTVM_LINUX_USER", "")
WORKSPACE = os.environ.get("AISTVM_WORKSPACE", "/tmp/aistvm-workspace")
MAX_COMMAND = 4000
MAX_OUTPUT = 65536
MAX_TIMEOUT = 300
DEFAULT_TIMEOUT = 60


def _cpu_sample():
    with open("/proc/stat", "r", encoding="utf-8") as handle:
        first = handle.readline().split()
    values = [int(part) for part in first[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return idle, sum(values)


def _memory():
    total = available = 0
    with open("/proc/meminfo", "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("MemTotal:"):
                total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                available = int(line.split()[1]) * 1024
    used = total - available
    percent = (used / total * 100.0) if total > 0 else 0.0
    return used, total, percent


def metrics_payload(previous):
    idle, total = _cpu_sample()
    cpu = 0.0
    if previous is not None:
        idle_delta = idle - previous[0]
        total_delta = total - previous[1]
        if total_delta > 0:
            cpu = max(0.0, min(100.0, (total_delta - idle_delta) * 100.0 / total_delta))
    used, total_mem, percent = _memory()
    with open("/proc/uptime", "r", encoding="utf-8") as handle:
        uptime = float(handle.read().split()[0])
    return (idle, total), {
        "cpu_percent": round(cpu, 1),
        "ram_percent": round(percent, 1),
        "ram_used_gb": round(used / 1073741824.0, 2),
        "ram_total_gb": round(total_mem / 1073741824.0, 2),
        "uptime_seconds": round(uptime, 1),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def build_argv(command):
    # Run as the session user so the workspace and permissions match the box
    # the user was promised. The runner user holds passwordless sudo.
    if LINUX_USER:
        return ["/usr/bin/sudo", "-H", "-u", LINUX_USER, "/bin/bash", "-lc", command]
    return ["/bin/bash", "-lc", command]


def run_command(command, timeout):
    os.makedirs(WORKSPACE, exist_ok=True)
    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            build_argv(command),
            cwd=WORKSPACE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        code = completed.returncode
        out = completed.stdout
        err = completed.stderr
    except subprocess.TimeoutExpired as expired:
        timed_out = True
        code = 124
        out = expired.stdout or b""
        err = expired.stderr or b""
    duration = int((time.monotonic() - started) * 1000)
    truncated = len(out) > MAX_OUTPUT or len(err) > MAX_OUTPUT
    return {
        "stdout": out[:MAX_OUTPUT].decode("utf-8", "replace"),
        "stderr": err[:MAX_OUTPUT].decode("utf-8", "replace"),
        "exit_code": code,
        "duration_ms": duration,
        "truncated": truncated,
        "timed_out": timed_out,
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    last_sample = None

    def log_message(self, *args):
        # Never write request lines or headers: the token travels in a header.
        return

    def _authorized(self):
        if not TOKEN:
            # Without a configured token nothing is authorized.
            return False
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].strip(), TOKEN)

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        if self.path == "/metrics":
            sample, payload = metrics_payload(Handler.last_sample)
            Handler.last_sample = sample
            self._send(200, payload)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        if self.path != "/exec":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_COMMAND * 4:
            self._send(400, {"error": "invalid body"})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "invalid json"})
            return
        command = body.get("command")
        if not isinstance(command, str) or not command.strip():
            self._send(400, {"error": "missing command"})
            return
        if len(command) > MAX_COMMAND:
            self._send(400, {"error": "command too long"})
            return
        timeout = body.get("timeout", DEFAULT_TIMEOUT)
        if not isinstance(timeout, int) or timeout < 1 or timeout > MAX_TIMEOUT:
            timeout = DEFAULT_TIMEOUT
        self._send(200, run_command(command, timeout))


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("AISTVM terminal agent listening on port " + str(PORT), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
