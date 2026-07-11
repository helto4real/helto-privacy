import pytest

from helto_privacy import PrivateByDefaultModeAdapter


def test_private_by_default_mode_adapter_accepts_only_declared_modes():
    adapter = PrivateByDefaultModeAdapter()

    assert adapter.read_declared_mode("scope") == "private"
    adapter.write_declared_mode("scope", "public")
    assert adapter.read_declared_mode("scope") == "public"

    with pytest.raises(ValueError):
        adapter.write_declared_mode("scope", "automatic")
