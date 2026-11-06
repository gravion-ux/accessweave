"""Offline identity-relationship and directory-permission review.

AccessWeave reads an explicitly exported identity inventory. It never queries a
directory service, collects credentials, or contacts a remote endpoint.
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "DANGEROUS_ROLES",
    "analyze_inventory",
    "relationship_edges",
]

# Group names that indicate broad administrative privilege. Matching is done on
# the normalised (lower-case, trimmed) group name.
DANGEROUS_ROLES = {
    "administrator",
    "administrators",
    "domain administrator",
    "domain admins",
    "enterprise administrator",
    "enterprise admins",
    "global administrator",
    "schema admins",
}

# Inventory fields that mark a principal as privileged directly.
PRIVILEGED_FLAGS = ("privileged", "is_admin", "privilege_escalation")

# Inventory fields that state whether multi-factor authentication is enabled.
MFA_FLAGS = ("mfa_enabled", "has_mfa", "mfa")


def _principals(data: Any) -> list[tuple[Any, dict]]:
    """Return ``(name_hint, principal)`` pairs from an inventory.

    Inventories are exported either as a list of principal objects or as a map
    from principal name to principal object. Both shapes are accepted so a
    differently shaped export does not silently produce an empty report.
    """
    if not isinstance(data, dict):
        return []
    principals = data.get("principals")
    if isinstance(principals, dict):
        return [(key, value) for key, value in principals.items() if isinstance(value, dict)]
    if not isinstance(principals, (list, tuple)):
        return []
    return [(None, principal) for principal in principals if isinstance(principal, dict)]


def _normalise_groups(principal: dict) -> list[str]:
    """Return the sorted, de-duplicated group names of a principal."""
    groups = principal.get("groups")
    if groups is None:
        return []
    if isinstance(groups, str):
        groups = [groups]
    if not isinstance(groups, (list, tuple, set)):
        return []
    values: set[str] = set()
    for group in groups:
        if isinstance(group, bool):
            # A boolean is never a group name.
            continue
        if isinstance(group, str):
            text = group.strip().lower()
        elif isinstance(group, int):
            text = str(group)
        else:
            continue
        if text:
            values.add(text)
    # Sorting keeps the report stable across runs: a set has no defined order.
    return sorted(values)


def _principal_name(principal: dict, hint: Any, index: int) -> str:
    """Return a stable, non-empty display name for a principal."""
    name = principal.get("name")
    if name is None and isinstance(hint, str):
        name = hint
    if name is None:
        return f"unknown-{index}"
    text = str(name).strip()
    return text or f"unknown-{index}"


def _is_explicitly_privileged(principal: dict) -> bool:
    """True when the inventory marks the principal as privileged itself."""
    for flag in PRIVILEGED_FLAGS:
        value = principal.get(flag)
        if isinstance(value, bool) and value:
            return True
    return False


def _mfa_state(principal: dict) -> bool | None:
    """Return True/False when the inventory states the MFA state, else None."""
    for flag in MFA_FLAGS:
        if flag not in principal:
            continue
        value = principal.get(flag)
        if isinstance(value, bool):
            return value
        if isinstance(value, dict):
            enabled = value.get("enabled")
            if isinstance(enabled, bool):
                return enabled
    return None


def _permissions(principal: dict) -> list[str]:
    """Return the sorted permission labels granted to a principal."""
    raw = principal.get("permissions")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple, set)):
        return []
    labels: set[str] = set()
    for item in raw:
        if isinstance(item, str):
            text = item.strip()
            if text:
                labels.add(text)
        elif isinstance(item, dict):
            action = item.get("action")
            resource = item.get("resource")
            action_text = action.strip() if isinstance(action, str) else ""
            resource_text = resource.strip() if isinstance(resource, str) else ""
            if action_text and resource_text:
                labels.add(f"{action_text} on {resource_text}")
            elif action_text or resource_text:
                labels.add(action_text or resource_text)
    return sorted(labels)


def analyze_inventory(data: dict) -> list[dict]:
    """Report privileged memberships and missing MFA on privileged accounts."""
    findings: list[dict] = []
    for index, (hint, principal) in enumerate(_principals(data)):
        name = _principal_name(principal, hint, index)
        groups = _normalise_groups(principal)
        privileged = sorted(set(groups) & DANGEROUS_ROLES)
        explicit = _is_explicitly_privileged(principal)
        if privileged or explicit:
            finding = {
                "rule_id": "ADP001",
                "severity": "high",
                "principal": name,
                "privileged_groups": privileged,
                "recommendation": (
                    "Validate business need, remove unnecessary membership, and review recent changes."
                ),
            }
            if explicit and not privileged:
                finding["privilege_source"] = "explicit-inventory-flag"
            findings.append(finding)
        if privileged or explicit:
            mfa = _mfa_state(principal)
            if mfa is False:
                findings.append(
                    {
                        "rule_id": "ADP002",
                        "severity": "high",
                        "principal": name,
                        "privileged_groups": privileged,
                        "recommendation": (
                            "Require multi-factor authentication for privileged accounts before "
                            "the membership is approved."
                        ),
                    }
                )
    return findings


def relationship_edges(data: dict) -> list[dict]:
    """Return membership and permission edges for the identity graph."""
    edges: list[dict] = []
    for index, (hint, principal) in enumerate(_principals(data)):
        name = _principal_name(principal, hint, index)
        for group in _normalise_groups(principal):
            edges.append({"from": name, "relation": "member_of", "to": group})
        for permission in _permissions(principal):
            edges.append({"from": name, "relation": "has_permission", "to": permission})
    return edges
