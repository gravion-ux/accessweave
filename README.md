# AccessWeave

> Offline identity-relationship and directory-permission review from explicitly exported inventory data.

**Status:** MVP scaffold / research prototype. Not production-certified.

## Features
- Import normalized JSON identity inventories.
- Build principal-to-resource edges.
- Flag broad privileged memberships for analyst review.
- Flag privileged principals that explicitly have no multi-factor authentication.
- Export explainable graph paths and findings.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
pytest
```

## Command-line usage

```bash
accessweave inventory.json                      # review an inventory and print the report
accessweave inventory.json --output report.json # also write the report to a file
accessweave inventory.json --fail-on-findings   # exit 1 when at least one finding is reported
```

| Exit code | Meaning |
| --- | --- |
| `0` | The inventory was reviewed and the report was produced. |
| `1` | The input could not be used, the report could not be written, or `--fail-on-findings` was given and findings exist. |
| `2` | The command line itself was wrong (for example a path that does not exist). |

Problems are reported as one-line messages. The command never prints a Python
traceback, so it can be used directly in a CI pipeline.

## Rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `ADP001` | high | A principal that belongs to a dangerous or broadly privileged group. |
| `ADP002` | high | A privileged principal whose inventory explicitly records that multi-factor authentication is disabled. |

`ADP002` only fires on explicit evidence in the inventory (`mfa_enabled: false`
or `mfa: { enabled: false }`). A principal with no multi-factor information at
all is not reported, because the inventory does not prove anything in that
case.

## Python API

```python
from pathlib import Path

from accessweave import analyze_inventory, relationship_edges

inventory = {"principals": [{"name": "svc-build", "groups": ["platform-admin"]}]}

for finding in analyze_inventory(inventory):
    print(finding["rule_id"], finding["principal"], finding["recommendation"])

for edge in relationship_edges(inventory):
    print(edge["from"], edge["relation"], "->", edge["to"])
```

## Safety and scope
Offline analysis only. No credential collection, domain authentication, remote enumeration, lateral movement, or exploitation is implemented. The tool reads a JSON file that the operator exported; it never contacts a directory service.

## Roadmap
- [x] Stable public API and versioned schemas
- [x] More unit, integration and adversarial tests
- [ ] Reproducible benchmarks and sample datasets
- [ ] Signed releases and dependency review
- [x] Documentation and contribution guide

## License
MIT. See [LICENSE](LICENSE). The license file carries the complete MIT text, including the warranty and liability clauses.
