"""Image references with registry/namespace slashes must validate (fork fix)."""
import pytest

from ssh_mcp.tools.docker._helpers import _validate_image


@pytest.mark.parametrize(
    "ref",
    [
        "nginx",
        "nginx:1.27",
        "stilldeadcode/radiance",
        "stilldeadcode/radiance:latest",
        "ghcr.io/org/team/app:v1",
        "registry:5000/app",
        "alpine@sha256:" + "a" * 64,
    ],
)
def test_valid_image_refs(ref):
    assert _validate_image(ref) == ref


@pytest.mark.parametrize(
    "ref",
    ["", "-rm", "nginx;id", "nginx latest", "$(id)", "a`b`", "nginx:*", "a\nb", "x" * 257],
)
def test_invalid_image_refs(ref):
    with pytest.raises(ValueError):
        _validate_image(ref)
