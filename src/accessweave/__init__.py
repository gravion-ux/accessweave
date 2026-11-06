"""AccessWeave: offline identity-relationship and directory-permission review.

Public API
----------
``analyze_inventory``     privileged memberships and missing MFA findings
``relationship_edges``    membership and permission edges for the identity graph
"""
from .analyzer import DANGEROUS_ROLES, analyze_inventory, relationship_edges

__all__ = [
    "DANGEROUS_ROLES",
    "__version__",
    "analyze_inventory",
    "relationship_edges",
]

__version__ = "0.2.0"
