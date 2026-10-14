# Contributing

## Setup

```bash
uv sync
make check
```

## Requirements for every change

- `make check` passes: ruff, black, mypy `--strict`, bandit, contract drift,
  tests with at least 90% branch coverage.
- New behaviour has tests. Security controls need adversarial cases in
  `tests/security`; dependency failure modes belong in `tests/chaos`.
- API or schema changes: run `python -m agent_control_plane.contracts` and
  record them in `CHANGELOG.md`.
- Changes to `policies/control-plane.yaml` come with tests for the rules
  they add or change.
- Architecturally significant decisions get an ADR in
  `docs/architecture/adr/`.
- No credentials, customer data or PHI in code, tests or fixtures. Use
  synthetic data only.

## Commit messages

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`). Breaking changes use `!` and a `BREAKING CHANGE:` footer.

## Review

Changes to `src/agent_control_plane/security`, `src/agent_control_plane/orchestration`,
`policies/` or `deployments/` need approval from a code owner (see `CODEOWNERS`).
