# AccessWeave

> Offline identity-relationship and directory-permission review from explicitly exported inventory data.

**Status:** MVP scaffold / research prototype. Not production-certified.

## Features
- Import normalized JSON identity inventories.
- Build principal-to-resource edges.
- Flag broad privileged memberships for analyst review.
- Export explainable graph paths and findings.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
pytest
```

## Safety and scope
Offline analysis only. No credential collection, domain authentication, remote enumeration, lateral movement, or exploitation is implemented.

## Roadmap
- [ ] Stable public API and versioned schemas
- [ ] More unit, integration and adversarial tests
- [ ] Reproducible benchmarks and sample datasets
- [ ] Signed releases and dependency review
- [ ] Documentation and contribution guide

## License
MIT. See [LICENSE](LICENSE).
