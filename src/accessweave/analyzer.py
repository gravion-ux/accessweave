DANGEROUS_ROLES = {"domain admins", "enterprise admins", "schema admins", "administrators"}

def _principals(data):
    if not isinstance(data,dict): return []
    principals=data.get("principals")
    if not isinstance(principals,(list,tuple)): return []
    return [p for p in principals if isinstance(p,dict)]

def _normalise_groups(principal):
    groups=principal.get("groups")
    if groups is None: return []
    if isinstance(groups,str): groups=[groups]
    if not isinstance(groups,(list,tuple,set)): return []
    return [str(g).strip().lower() for g in groups if isinstance(g,(str,int,float))]

def _principal_name(principal):
    name=principal.get("name")
    if name is None: return "unknown"
    return str(name).strip() or "unknown"

def analyze_inventory(data: dict):
    findings = []
    for principal in _principals(data):
        name = _principal_name(principal)
        groups = set(_normalise_groups(principal))
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
    for principal in _principals(data):
        name = _principal_name(principal)
        for group in _normalise_groups(principal):
            edges.append({"from": name, "relation": "member_of", "to": group})
    return edges
