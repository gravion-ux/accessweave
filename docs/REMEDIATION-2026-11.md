# Remediation notes — 2026-11

This document records the audit and remediation applied to AccessWeave in November 2026.
It is additive: the original README, SECURITY.md, CONTRIBUTING.md and example files
remain in the repository and were updated only where they were inaccurate or
inconsistent.

## Method

Every source file was read line by line and each suspected defect was confirmed with
an executable regression test. The new tests were first run against the previously
published revision to confirm the defect was real (red phase: 22 failing tests), and
only then were the fixes applied (green phase: 33 passing tests).

## Defects fixed

| Severity | Defect | Fix |
| --- | --- | --- |
| Medium | The command line raised a raw Python traceback for a missing file, invalid JSON, a byte-order mark, a JSON root that was not an object, and for an unwritable report file | `cli.main` reports one-line messages and uses exit codes `0` / `1` / `2` |
| Medium | The order of the principal-to-resource edges depended on the iteration order of a `set`, so the same inventory produced a different report on every run | Groups are sorted and de-duplicated before the edges are built |
| Medium | An inventory whose `principals` entry was a map (object keyed by principal name) was ignored completely, even though the documented format allows it | A map is accepted; the key is used as the principal name |
| Medium | A privileged principal with multi-factor authentication explicitly disabled was never reported | New rule `ADP002`, raised only on explicit `mfa_enabled: false` or `mfa: { enabled: false }` evidence |
| Low | A boolean group value was stringified into the text `True` and then treated as a group name | Boolean group values are ignored |
| Low | Several principals without a name were collapsed into a single `unknown` node, which merged unrelated accounts in the graph | Nameless principals get a stable `unknown-<index>` identity |
| Low | The README promised principal-to-resource permission edges, but the exporter only emitted membership edges | Permissions are exported as `has_permission` edges, and explicit `privileged` / `is_admin` / `privilege_escalation` flags are honored |
| Low | The package exposed no public API and the report carried no format marker | `accessweave.__all__`, `accessweave.__version__`, and `schema_version` in the report |

## Documentation and spelling corrections

- `LICENSE` shipped a truncated MIT text: the warranty and liability clauses were
  missing. The complete, canonical MIT text is now in place.
- Spelling was inconsistent across the same file set (`behaviour` in `CONTRIBUTING.md`
  against `authorization` in `SECURITY.md` and `normalized` in `README.md`). The
  prose now uses one convention throughout: American English.
- The roadmap listed "Documentation and contribution guide" as unfinished while
  `CONTRIBUTING.md`, `SECURITY.md` and this file exist. The checklist now reflects
  reality, and "Stable public API and versioned report schema" is marked complete.
- The README documented no command-line usage, no exit codes and no rule catalogue,
  although the project ships a console script and two rules. All three are now
  documented.
- A dictionary spelling scan (`codespell`) now reports no misspelling in this
  repository.

## Continuous integration hardening

The workflow previously ran the test suite only. It now also runs a credential scan
on every push and pull request.

| Job | What it does |
| --- | --- |
| `secret-scan` | Runs `scripts/scan-secrets.py`, which fails the build when the repository contains a high-confidence credential pattern (cloud keys, tokens, private key blocks, JWTs) or a file that must never be committed (`.env`, `*.pem`, `*.key`, `*.p12`, `id_rsa`, credential files) |

The scanner is the one already used by the Gravion Toolkit split repositories, so
every toolkit project now shares one definition of what counts as a secret. A
"soft" match, such as a dummy `api_key` inside a test fixture, is reported for
review but does not fail the build.

### Executable bit on the secret scanner

The first run of the new pipeline failed on the Ubuntu runner with
`EXE001 Shebang is present but file is not executable`. Git on Windows has no
execute bit, so `scripts/scan-secrets.py` was published with mode `100644`
although it carries a `#!/usr/bin/env python3` shebang, and the checkout on
the runner produced a non-executable file. The scanner is now committed with
mode `100755`, which is what the shebang promises, and it can also be run
directly as `./scripts/scan-secrets.py .`.

## Verification

| Check | Before | After |
| --- | --- | --- |
| Secret scan in CI | absent | present |
| Secret scanner file mode | `100644` (not executable) | `100755` (executable) |
| Tests | 7 | 33 |
| `ruff check .` | clean | clean |
| Rules | 1 (`ADP001`) | 2 (`ADP001`, `ADP002`) |

## Residual limitations

- `ADP002` needs explicit evidence. An inventory that simply does not mention
  multi-factor authentication produces no finding, because the absence of a field
  is not proof that the account is unprotected.
- The dangerous-group list is a fixed set of role names. A directory that uses
  different names for privileged groups is not detected; the explicit
  `privileged` / `is_admin` / `privilege_escalation` flags cover that case.
- AccessWeave never contacts a directory service and never resolves a principal to
  a real account. Every finding is a review hint about the exported inventory.
