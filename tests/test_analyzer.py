import accessweave
from accessweave import analyzer
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


# --- deterministic output ----------------------------------------------------


def test_group_order_is_deterministic_for_set_input():
    data={"principals":[{"name":"svc","groups":{"zeta","alpha","middle"}}]}
    first=relationship_edges(data)
    second=relationship_edges(data)
    assert first==second
    assert [edge["to"] for edge in first]==["alpha","middle","zeta"]


def test_duplicate_groups_produce_a_single_edge():
    data={"principals":[{"name":"svc","groups":["Administrators","administrators"]}]}
    assert len(relationship_edges(data))==1


def test_boolean_group_value_is_ignored():
    data={"principals":[{"name":"svc","groups":[True,"Administrators"]}]}
    edges=relationship_edges(data)
    assert [edge["to"] for edge in edges]==["administrators"]


# --- inventory shapes --------------------------------------------------------


def test_principals_exported_as_a_map_are_analyzed():
    data={"principals":{"alice":{"groups":["Administrators"]}}}
    findings=analyze_inventory(data)
    assert findings and findings[0]["principal"]=="alice"


def test_principal_name_prefers_the_explicit_name_over_the_map_key():
    data={"principals":{"alice":{"name":"alice@example.com","groups":["Administrators"]}}}
    findings=analyze_inventory(data)
    assert findings[0]["principal"]=="alice@example.com"


def test_principals_without_a_name_get_distinct_identifiers():
    data={"principals":[{"groups":["Administrators"]},{"groups":["Administrators"]}]}
    findings=analyze_inventory(data)
    assert findings[0]["principal"]!=findings[1]["principal"]


# --- privileged accounts without MFA -----------------------------------------


def test_privileged_principal_without_mfa_is_flagged():
    data={"principals":[{"name":"svc","groups":["Administrators"],"mfa_enabled":False}]}
    rules=[finding["rule_id"] for finding in analyze_inventory(data)]
    assert "ADP002" in rules


def test_privileged_principal_with_mfa_is_not_flagged():
    data={"principals":[{"name":"svc","groups":["Administrators"],"mfa_enabled":True}]}
    rules=[finding["rule_id"] for finding in analyze_inventory(data)]
    assert "ADP002" not in rules


def test_non_privileged_principal_without_mfa_is_not_flagged():
    data={"principals":[{"name":"svc","groups":["Readers"],"mfa_enabled":False}]}
    assert analyze_inventory(data)==[]


def test_missing_mfa_evidence_is_not_treated_as_missing_mfa():
    data={"principals":[{"name":"svc","groups":["Administrators"]}]}
    rules=[finding["rule_id"] for finding in analyze_inventory(data)]
    assert "ADP002" not in rules


def test_mfa_map_form_is_honoured():
    data={"principals":[{"name":"svc","groups":["Administrators"],"mfa":{"enabled":False}}]}
    rules=[finding["rule_id"] for finding in analyze_inventory(data)]
    assert "ADP002" in rules


def test_explicitly_privileged_principal_is_flagged():
    data={"principals":[{"name":"svc","privileged":True}]}
    findings=analyze_inventory(data)
    assert findings and findings[0]["rule_id"]=="ADP001"
    assert findings[0]["privilege_source"]=="explicit-inventory-flag"


# --- permission edges --------------------------------------------------------


def test_permission_edges_are_emitted():
    data={"principals":[{"name":"svc","permissions":["s3:GetObject","arn:aws:s3:::b/*"]}]}
    edges=relationship_edges(data)
    assert {edge["relation"] for edge in edges}=={"has_permission"}
    assert [edge["to"] for edge in edges]==["arn:aws:s3:::b/*","s3:GetObject"]


def test_permission_edge_for_an_action_and_a_resource_pair():
    data={"principals":[{"name":"svc","permissions":[{"action":"s3:GetObject","resource":"arn:aws:s3:::b/*"}]}]}
    edges=relationship_edges(data)
    assert edges[0]["to"]=="s3:GetObject on arn:aws:s3:::b/*"


def test_membership_and_permission_edges_coexist():
    data={"principals":[{"name":"svc","groups":["Readers"],"permissions":["s3:GetObject"]}]}
    relations={edge["relation"] for edge in relationship_edges(data)}
    assert relations=={"member_of","has_permission"}


# --- public API --------------------------------------------------------------


def test_package_exposes_the_public_api():
    assert accessweave.analyze_inventory is analyze_inventory
    assert accessweave.relationship_edges is relationship_edges
    assert accessweave.__version__


def test_dangerous_roles_are_exported():
    assert "administrators" in analyzer.DANGEROUS_ROLES
