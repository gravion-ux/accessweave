import json

from accessweave import cli


def _write_inventory(tmp_path, payload, name="inventory.json", encoding="utf-8"):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding=encoding)
    return path


def test_cli_reports_a_missing_file_without_a_traceback(tmp_path, capsys):
    code = cli.main([str(tmp_path / "absent.json")])
    captured = capsys.readouterr()
    assert code == cli.EXIT_USAGE
    assert "accessweave:" in captured.err
    assert "Traceback" not in captured.err


def test_cli_reports_invalid_json_without_a_traceback(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    code = cli.main([str(path)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_INVALID_INPUT
    assert "invalid JSON" in captured.err
    assert "Traceback" not in captured.err


def test_cli_rejects_a_non_object_inventory_root(tmp_path, capsys):
    path = tmp_path / "list.json"
    path.write_text(json.dumps(["not-an-inventory"]), encoding="utf-8")
    code = cli.main([str(path)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_INVALID_INPUT
    assert "must contain a JSON object" in captured.err
    assert "Traceback" not in captured.err


def test_cli_reads_an_inventory_that_starts_with_a_byte_order_mark(tmp_path, capsys):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps({"principals": [{"name": "svc", "groups": ["Administrators"]}]}),
                    encoding="utf-8-sig")
    code = cli.main([str(path)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_OK
    report = json.loads(captured.out)
    assert report["findings"][0]["rule_id"] == "ADP001"


def test_cli_prints_a_json_report(tmp_path, capsys):
    path = _write_inventory(tmp_path, {"principals": [{"name": "svc", "groups": ["Administrators"]}]})
    cli.main([str(path)])
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == "AccessWeave"
    assert report["mode"] == "offline-inventory-review"
    assert report["schema_version"] == 1
    assert report["edges"]
    assert "notice" in report


def test_cli_writes_the_report_to_the_output_path(tmp_path, capsys):
    path = _write_inventory(tmp_path, {"principals": [{"name": "svc", "groups": ["Administrators"]}]})
    output = tmp_path / "report.json"
    code = cli.main([str(path), "--output", str(output)])
    capsys.readouterr()
    assert code == cli.EXIT_OK
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["findings"][0]["rule_id"] == "ADP001"


def test_cli_reports_an_unwritable_output_path_without_a_traceback(tmp_path, capsys):
    path = _write_inventory(tmp_path, {"principals": [{"name": "svc", "groups": ["Administrators"]}]})
    output = tmp_path / "missing-directory" / "report.json"
    code = cli.main([str(path), "--output", str(output)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_INVALID_INPUT
    assert "accessweave:" in captured.err
    assert "Traceback" not in captured.err


def test_cli_fail_on_findings_returns_a_failing_status(tmp_path, capsys):
    path = _write_inventory(tmp_path, {"principals": [{"name": "svc", "groups": ["Administrators"]}]})
    code = cli.main([str(path), "--fail-on-findings"])
    capsys.readouterr()
    assert code == cli.EXIT_INVALID_INPUT


def test_cli_fail_on_findings_succeeds_on_a_clean_inventory(tmp_path, capsys):
    path = _write_inventory(tmp_path, {"principals": [{"name": "svc", "groups": ["Readers"]}]})
    code = cli.main([str(path), "--fail-on-findings"])
    capsys.readouterr()
    assert code == cli.EXIT_OK
