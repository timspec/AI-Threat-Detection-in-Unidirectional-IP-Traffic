"""
tests/test_check_capture.py — Unit tests for tools/check_capture.py

Verifies that:
 1. list_interfaces() returns a list.
 2. print_interfaces() handles an empty list without crashing.
 3. print_interfaces() formats a mock interface list correctly.
"""

from unittest.mock import patch

from tools.check_capture import list_interfaces, print_interfaces


def test_list_interfaces_returns_list():
    """list_interfaces() must return a list (possibly empty if Npcap missing)."""
    result = list_interfaces()
    assert isinstance(result, list)


def test_print_interfaces_empty(capsys):
    """print_interfaces([]) should print a 'no interfaces' message."""
    print_interfaces([])
    captured = capsys.readouterr()
    assert "No interfaces found" in captured.out


def test_print_interfaces_with_data(capsys):
    """print_interfaces() should print each interface's details."""
    mock_ifaces = [
        {
            "name": "Ethernet0",
            "description": "Intel PRO/1000",
            "ips": ["192.168.1.10"],
            "mac": "AA:BB:CC:DD:EE:FF",
        },
        {
            "name": "WiFi",
            "description": "Realtek 802.11ac",
            "ips": ["10.0.0.5", "fe80::1"],
            "mac": "11:22:33:44:55:66",
        },
    ]
    print_interfaces(mock_ifaces)
    captured = capsys.readouterr()

    assert "Found 2 network interface(s)" in captured.out
    assert "Intel PRO/1000" in captured.out
    assert "Realtek 802.11ac" in captured.out
    assert "192.168.1.10" in captured.out
    assert "AA:BB:CC:DD:EE:FF" in captured.out
    assert "Npcap + Scapy are working correctly" in captured.out


def test_list_interfaces_no_scapy():
    """If scapy.arch.windows is unavailable, list_interfaces returns []."""
    with patch.dict("sys.modules", {"scapy.arch.windows": None}):
        # Force re-import failure by patching at the import level
        with patch("builtins.__import__", side_effect=ImportError("mock")):
            result = list_interfaces()
            assert result == []
