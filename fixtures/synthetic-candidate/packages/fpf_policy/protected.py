"""Synthetic protected-path policy used by Controller acceptance tests."""

PROTECTED_PATHS = frozenset(
    {
        "docs/coordination/self-hosting-protocol.md",
    }
)


def is_protected(path: str) -> bool:
    return path.replace("\\", "/").strip().lower() in PROTECTED_PATHS
