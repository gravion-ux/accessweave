"""Regression tests for the inventory size limit."""
from __future__ import annotations

import pytest

from accessweave import cli


def test_oversized_inventory_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "MAX_INVENTORY_BYTES", 16)
    path = tmp_path / "inventory.json"
    path.write_text('{"identities": [], "padding": "xxxxxxxxxxxxxxxx"}', encoding="utf-8")
    with pytest.raises(cli.InventoryFormatError, match="size limit"):
        cli._load_inventory(path)


def test_oversized_inventory_exits_invalid_input(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "MAX_INVENTORY_BYTES", 16)
    path = tmp_path / "inventory.json"
    path.write_text('{"identities": [], "padding": "xxxxxxxxxxxxxxxx"}', encoding="utf-8")
    assert cli.main([str(path)]) == cli.EXIT_INVALID_INPUT
    assert "size limit" in capsys.readouterr().err
