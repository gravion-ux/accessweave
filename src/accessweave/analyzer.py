DANGEROUS_ROLES = {"domain admins", "enterprise admins", "schema admins", "administrators"}

def analyze_inventory(data: dict):
    findings = []
    principals = data.get("principals", [])
    for principal in principals:
        name = str(principal.get("name", "unknown"))
        groups = {str(g).strip().lower() for g in principal.get("groups", [])}
        privileged = sorted(groups & DANGEROUS_ROLES)
        if privileged:
            findings.append({
                "rule_id": "ADP001", "severity": "high",
                "principal": name, "privileged_groups": privileged,
                "recommendation": "Validate business need, remove unnecessary membership, and review recent changes."
            })
    return findings

def relationship_edges(data: dict):
    edges = []
    for principal in data.get("principals", []):
        for group in principal.get("groups", []):
            edges.append({"from": principal.get("name", "unknown"), "relation": "member_of", "to": group})
    return edges
