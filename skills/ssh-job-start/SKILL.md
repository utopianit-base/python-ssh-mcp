---
description: Run long commands as named background jobs that survive timeouts and disconnects
---

# `ssh_job_start` / `ssh_job_status` / `ssh_job_logs` / `ssh_job_cancel`

**Tier:** dangerous | **Group:** `exec` | **Tags:** `{dangerous, group:exec}`

Use these instead of `ssh_exec_run` / `ssh_exec_run_streaming` for anything
that may run longer than about 60 seconds. MCP gateways often cut calls off
at 60s and may retry them; a job keeps running and cannot be started twice.

Each job is the systemd unit `mcpjob-<name>.service`, created with
`sudo -n systemd-run`. It runs as the SSH login user unless `as_root=true`
(which needs `ALLOW_SUDO=true`). Output goes to the journal; the exit status
is kept on the unit until `ssh_job_cancel`.

## Workflow

1. `ssh_job_start(host, name, command)` returns immediately. Exit code non-zero
   with "already loaded" / "already exists" in stderr means a job of that name
   exists: check its status, do NOT pick a new name to get around it.
2. Poll `ssh_job_status(host, name)` -> `state`: `running` | `succeeded` |
   `failed` | `not_found`, plus `exit_code`, `pid`, `started`, `finished`.
3. `ssh_job_logs(host, name, lines=200, since="10 min ago")` for output.
4. `ssh_job_cancel(host, name)` stops a running job and frees the name. Call it
   after a finished job too, before starting one with the same name again.

The command passes the same allowlist check as `ssh_exec_run`. Requires systemd
and a sudoers entry for the SSH user on the target.
