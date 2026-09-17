# SPDX-License-Identifier: Apache-2.0
"""`leeward serve` as a process: what it says when it starts, and that it stops cleanly."""

from __future__ import annotations

import json
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, cast

from tests.support import REPO_ROOT


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return cast("int", probe.getsockname()[1])


def test_serve_reports_its_start_as_json_and_stops_on_sigint(tmp_path: Path) -> None:
    port = free_port()
    config = tmp_path / "leeward.yaml"
    config.write_text(
        f"data_dir: {tmp_path / 'data'}\nsurfaces:\n  fetch:\n    enabled: true\n"
        f"    listen: 127.0.0.1:{port}\n",
        encoding="utf-8",
    )
    command = [sys.executable, "-m", "leeward", "serve", "--json", "--config", str(config)]
    server = subprocess.Popen(
        command, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        assert server.stdout is not None
        started = cast("dict[str, Any]", json.loads(server.stdout.readline()))
        status: dict[str, Any] = {}
        for _ in range(100):
            try:
                with urllib.request.urlopen(
                    f"{started['listening']}/leeward/status", timeout=1
                ) as reply:
                    status = cast("dict[str, Any]", json.load(reply))
                break
            except OSError:
                time.sleep(0.05)
        server.send_signal(signal.SIGINT)
        code = server.wait(timeout=20)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()

    assert started["listening"] == f"http://127.0.0.1:{port}"
    assert (started["surfaces"], started["warnings"]) == (["fetch"], [])
    assert status["data_dir"] == str(tmp_path / "data")
    assert code == 0
