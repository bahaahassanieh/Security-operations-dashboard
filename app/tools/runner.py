"""Least-privilege subprocess execution for security tools.

There is deliberately no way to run a shell here. Commands are argument arrays, run with a
minimal environment, a private working directory, resource limits and a hard timeout.
"""
from __future__ import annotations

import hashlib
import os
import resource
import signal
import subprocess  # nosec B404  Used only with argument arrays and shell=False.
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

MAX_OUTPUT_BYTES = 200 * 1024 * 1024
MAX_ARGUMENT_LENGTH = 4096
_TERMINATE_GRACE_SECONDS = 3
_CANCEL_POLL_SECONDS = 1.0


class UnsafeCommand(ValueError):
    """Raised when a command fails validation and must not be executed."""


@dataclass(frozen=True)
class ToolCommand:
    """A fully specified tool invocation."""

    executable: str
    arguments: tuple[str, ...]
    workdir: Path
    timeout_seconds: int


@dataclass(frozen=True)
class ToolResult:
    """The outcome of running a tool."""

    status: str  # completed, failed, timeout or cancelled
    exit_code: int | None
    duration_ms: int
    output_path: Path
    error_path: Path
    output_sha256: str
    output_bytes: int


def _validate(command: ToolCommand) -> None:
    if not os.path.isabs(command.executable):
        raise UnsafeCommand("The executable must be an absolute path.")
    if command.timeout_seconds <= 0:
        raise UnsafeCommand("A positive timeout is required.")
    for argument in command.arguments:
        if not isinstance(argument, str):
            raise UnsafeCommand("Arguments must be strings.")
        if "\x00" in argument or len(argument) > MAX_ARGUMENT_LENGTH:
            raise UnsafeCommand("Argument contains a NUL byte or is too long.")


def _apply_limits(pid: int) -> None:
    """Disable core dumps and bound output size for a started tool."""
    try:
        resource.prlimit(pid, resource.RLIMIT_CORE, (0, 0))
        resource.prlimit(pid, resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
    except (OSError, ValueError):  # The process has already exited.
        pass


def minimal_environment(workdir: Path) -> dict[str, str]:
    """Build the only environment a tool receives. Platform secrets are never inherited."""
    home = workdir / ".home"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(workdir),
        "LANG": "C.UTF-8",
        "NO_COLOR": "1",
    }


def _stop_process_group(process: subprocess.Popen) -> None:
    """Terminate the tool and every child it started."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_tool(command: ToolCommand, should_cancel: Callable[[], bool] | None = None) -> ToolResult:
    """Execute a validated command, capturing stdout and stderr to private files."""
    _validate(command)
    command.workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_path = command.workdir / "stdout.txt"
    error_path = command.workdir / "stderr.txt"
    started = time.monotonic()
    status = None

    with output_path.open("wb") as stdout, error_path.open("wb") as stderr:
        process = subprocess.Popen(  # nosec B603  Validated argument array, never a shell.
            [command.executable, *command.arguments],
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            cwd=command.workdir,
            env=minimal_environment(command.workdir),
            shell=False,
            close_fds=True,
            start_new_session=True,
            umask=0o077,
        )
        _apply_limits(process.pid)
        next_cancel_check = started
        while process.poll() is None:
            now = time.monotonic()
            if now - started >= command.timeout_seconds:
                status = "timeout"
                _stop_process_group(process)
                break
            if should_cancel is not None and now >= next_cancel_check:
                next_cancel_check = now + _CANCEL_POLL_SECONDS
                if should_cancel():
                    status = "cancelled"
                    _stop_process_group(process)
                    break
            time.sleep(0.1)

    exit_code = process.returncode
    if status is None:
        status = "completed" if exit_code == 0 else "failed"
    return ToolResult(
        status=status,
        exit_code=exit_code,
        duration_ms=int((time.monotonic() - started) * 1000),
        output_path=output_path,
        error_path=error_path,
        output_sha256=_sha256(output_path),
        output_bytes=output_path.stat().st_size,
    )
