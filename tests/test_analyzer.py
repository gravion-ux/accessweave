from accessweave.analyzer import analyze_inventory, relationship_edges


def test_flags_privileged_group():
    data={"principals":[{"name":"svc","groups":["Administrators"]}]}
    assert analyze_inventory(data)[0]["rule_id"] == "ADP001"
    assert len(relationship_edges(data)) == 1
