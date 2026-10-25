"""Job tier: long-running commands as named systemd transient units.

Tagged ``{"dangerous", "group:exec"}``. Each job is the system unit
``mcpjob-<name>.service`` created with ``sudo -n systemd-run``, so it outlives
the SSH connection and any MCP gateway timeout, keeps its log in the journal
and its exit status in the unit (``RemainAfterExit=yes``). The name is the
dedupe key: a retried ``ssh_job_start`` fails while a job of that name is
still loaded. ``ssh_job_cancel`` stops it and clears the name for reuse.

Jobs run as the SSH login user unless ``as_root=True`` (requires
``ALLOW_SUDO``). Requires systemd and a sudoers entry for the SSH user.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from fastmcp import Context

from ..app import mcp_server
from ..models.results import ExecResult
from ..services.audit import audited
from ..services.exec_policy import check_command
from ..ssh.exec import run as exec_run
from ._context import pool_from, require_posix, resolve_host, settings_from

_JOB_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
# journalctl --since forms: "2026-10-25 13:00:00", "10 min ago", "today".
_SINCE_RE = re.compile(r"^[A-Za-z0-9 :+.\-]{1,40}$")
_SHOW_PROPS = (
    "LoadState,ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,"
    "MainPID,ExecMainStartTimestamp,ExecMainExitTimestamp,User"
)


def _unit(name: str) -> str:
    if not _JOB_NAME_RE.match(name):
        raise ValueError(f"invalid job name {name!r}: must match [A-Za-z0-9][A-Za-z0-9_.-]{{0,63}}")
    return f"mcpjob-{name}.service"


def build_start(name: str, command: str, *, as_root: bool) -> str:
    unit = _unit(name)
    # ponytail: system units via sudo, not `systemd-run --user` -- user units
    # die at logout unless linger is enabled on every host.
    user = "" if as_root else ' --uid="$(id -un)" -p WorkingDirectory=~'
    return (
        f"sudo -n systemd-run --unit={unit} -p RemainAfterExit=yes{user} "
        f"--description={shlex.quote('ssh-mcp job ' + name)} -- sh -c {shlex.quote(command)}"
    )


def build_logs(name: str, *, lines: int, since: str | None) -> str:
    argv = ["sudo", "-n", "journalctl", "-u", _unit(name), "--no-pager", "-o", "short-iso", "-n", str(lines)]
    if since is not None:
        if not _SINCE_RE.match(since):
            raise ValueError(f"invalid since {since!r}: use e.g. '10 min ago' or '2026-10-25 13:00:00'")
        argv += ["--since", since]
    return shlex.join(argv)


def build_cancel(name: str) -> str:
    unit = shlex.quote(_unit(name))
    # stop unloads a RemainAfterExit unit; reset-failed clears a failed one.
    return f"sudo -n systemctl stop {unit}; sudo -n systemctl reset-failed {unit} 2>/dev/null; true"


def parse_show(stdout: str) -> dict[str, Any]:
    props = dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)
    if props.get("LoadState") == "not-found":
        state = "not_found"
    elif props.get("ActiveState") == "failed" or props.get("Result", "success") != "success":
        state = "failed"
    elif props.get("SubState") == "exited":
        state = "succeeded"
    elif props.get("ActiveState") in ("active", "activating", "deactivating"):
        state = "running"
    else:
        state = props.get("ActiveState", "unknown")
    code = props.get("ExecMainStatus", "")
    pid = props.get("MainPID", "0")
    return {
        "state": state,
        "exit_code": int(code) if state in ("succeeded", "failed") and code.isdigit() else None,
        "pid": int(pid) if pid.isdigit() and pid != "0" else None,
        "started": props.get("ExecMainStartTimestamp") or None,
        "finished": props.get("ExecMainExitTimestamp") or None,
        "user": None if state == "not_found" else props.get("User") or "root",
        "properties": props,
    }


async def _run(ctx: Context, host: str, cmd: str, tool: str) -> ExecResult:
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    require_posix(resolved, tool=tool, reason="uses systemd-run / systemctl / journalctl")
    conn = await pool.acquire(resolved)
    return await exec_run(
        conn,
        cmd,
        host=resolved.policy.hostname,
        timeout=float(settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
    )


@mcp_server.tool(tags={"dangerous", "group:exec"}, version="1.0")
@audited(tier="dangerous")
async def ssh_job_start(
    host: str,
    name: str,
    command: str,
    ctx: Context,
    as_root: bool = False,
) -> ExecResult:
    """Start ``command`` as a detached, named background job (systemd unit
    ``mcpjob-<name>``). Returns immediately; poll ``ssh_job_status`` /
    ``ssh_job_logs``. Use for anything that may exceed ~60s. Fails if a job of
    that name is still loaded -- safe to retry. ``ssh_job_cancel`` frees the name.
    """
    settings = settings_from(ctx)
    if as_root and not settings.ALLOW_SUDO:
        raise PermissionError("ssh_job_start as_root=True requires ALLOW_SUDO=true")
    check_command(command, resolve_host(ctx, host).policy, settings)
    return await _run(ctx, host, build_start(name, command, as_root=as_root), "ssh_job_start")


@mcp_server.tool(tags={"dangerous", "group:exec"}, version="1.0")
@audited(tier="dangerous")
async def ssh_job_status(host: str, name: str, ctx: Context) -> dict[str, Any]:
    """State of job ``name``: running | succeeded | failed | not_found, with
    exit code, PID and start/finish timestamps."""
    cmd = f"systemctl show {shlex.quote(_unit(name))} -p {_SHOW_PROPS}"
    result = await _run(ctx, host, cmd, "ssh_job_status")
    if result.exit_code != 0:
        return {"name": name, "state": "error", "stderr": result.stderr}
    return {"name": name, **parse_show(result.stdout)}


@mcp_server.tool(tags={"dangerous", "group:exec"}, version="1.0")
@audited(tier="dangerous")
async def ssh_job_logs(
    host: str,
    name: str,
    ctx: Context,
    lines: int = 200,
    since: str | None = None,
) -> ExecResult:
    """Journal output of job ``name`` (last ``lines``, max 5000). ``since`` takes
    journalctl syntax, e.g. ``"10 min ago"`` or ``"2026-10-25 13:00:00"``."""
    cmd = build_logs(name, lines=max(1, min(lines, 5000)), since=since)
    return await _run(ctx, host, cmd, "ssh_job_logs")


@mcp_server.tool(tags={"dangerous", "group:exec"}, version="1.0")
@audited(tier="dangerous")
async def ssh_job_cancel(host: str, name: str, ctx: Context) -> ExecResult:
    """Stop job ``name`` if running and clear it so the name can be reused.
    Logs stay in the journal. Also use after a job finishes, before restarting it."""
    return await _run(ctx, host, build_cancel(name), "ssh_job_cancel")
