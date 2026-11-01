from packages.fpf_policy.protected import is_protected


def test_protocol_is_protected() -> None:
    assert is_protected("docs/coordination/SELF-HOSTING-PROTOCOL.md") is True
