from accessweave.analyzer import analyze_inventory, relationship_edges


def test_flags_privileged_group():
    data={"principals":[{"name":"svc","groups":["Administrators"]}]}
    assert analyze_inventory(data)[0]["rule_id"] == "ADP001"
    assert len(relationship_edges(data)) == 1


def test_bare_string_group_is_treated_as_one_group():
    data={"principals":[{"name":"svc","groups":"Administrators"}]}
    findings=analyze_inventory(data)
    edges=relationship_edges(data)
    assert findings and findings[0]["privileged_groups"]==["administrators"]
    assert len(edges)==1 and edges[0]["to"]=="administrators"


def test_edge_group_matches_finding_group():
    data={"principals":[{"name":"svc","groups":[" Administrators "]}]}
    findings=analyze_inventory(data)
    edges=relationship_edges(data)
    assert findings[0]["privileged_groups"]==[edges[0]["to"]]


def test_missing_groups_yield_no_findings_or_edges():
    data={"principals":[{"name":"svc"}]}
    assert analyze_inventory(data)==[]
    assert relationship_edges(data)==[]


def test_null_groups_are_ignored():
    data={"principals":[{"name":"svc","groups":None}]}
    assert analyze_inventory(data)==[]
    assert relationship_edges(data)==[]


def test_non_dict_principal_is_ignored():
    data={"principals":["not-a-principal"]}
    assert analyze_inventory(data)==[]
    assert relationship_edges(data)==[]


def test_principal_name_is_consistent_between_findings_and_edges():
    data={"principals":[{"name":None,"groups":["Administrators"]}]}
    findings=analyze_inventory(data)
    edges=relationship_edges(data)
    assert findings[0]["principal"]==edges[0]["from"]
