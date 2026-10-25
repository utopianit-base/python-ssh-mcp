"""ssh_job_* command builders and `systemctl show` parsing (fork feature)."""

import pytest

from ssh_mcp.tools.job_tools import build_cancel, build_logs, build_start, parse_show


def test_start_runs_as_login_user_and_quotes_command():
    cmd = build_start("vram-test", "nvidia-smi; sleep 600 && echo 'done'", as_root=False)
    assert cmd.startswith("sudo -n systemd-run --unit=mcpjob-vram-test.service -p RemainAfterExit=yes")
    assert '--uid="$(id -un)"' in cmd
    assert cmd.endswith("-- sh -c 'nvidia-smi; sleep 600 && echo '\"'\"'done'\"'\"''")


def test_start_as_root_has_no_uid():
    assert "--uid" not in build_start("j", "true", as_root=True)


@pytest.mark.parametrize("name", ["", "-x", "a b", "a;id", "a/b", "$(id)", "x" * 65])
def test_bad_names_rejected(name):
    with pytest.raises(ValueError):
        build_start(name, "true", as_root=False)
    with pytest.raises(ValueError):
        build_cancel(name)


def test_logs_since_validated():
    assert build_logs("j", lines=50, since="10 min ago").endswith("-n 50 --since '10 min ago'")
    with pytest.raises(ValueError):
        build_logs("j", lines=50, since="now; id")


L = "LoadState=loaded\n"


@pytest.mark.parametrize(
    ("show", "state", "code"),
    [
        ("LoadState=not-found\nActiveState=inactive\nResult=success\nExecMainStatus=0", "not_found", None),
        (L + "ActiveState=active\nSubState=running\nResult=success\nMainPID=42", "running", None),
        (L + "ActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0", "succeeded", 0),
        (L + "ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=3", "failed", 3),
    ],
)
def test_parse_show(show, state, code):
    out = parse_show(show)
    assert (out["state"], out["exit_code"]) == (state, code)
