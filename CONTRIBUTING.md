# Contributing to NEXUS

Thanks for considering a contribution to NEXUS (TrustGeeks Security).

## Development setup

```bash
git clone https://github.com/trustgeeks/nexus.git
cd nexus
pip install -e ".[dev]"
pytest
```

## Ground rules

- **No stubs in main.** Every detector, parser, or graph feature merged to
  `main` must have real logic and real tests — not a `TODO` or `pass`.
- **Every detector needs fixture-based tests** proving both the
  true-positive case (it fires when it should) and, where relevant, a
  true-negative case (it doesn't fire on benign data).
- **Explainability over accuracy tricks.** A detector that can't explain
  *why* it fired (in terms of specific events/fields) doesn't belong in
  `nexus/detection`. This is a hard project value, not a style preference.
- **Type hints required** on all public functions.
- **Format/lint** with `black` and `ruff` before opening a PR (config in
  `pyproject.toml` once added; for now, match existing style).

## Pull request checklist

- [ ] `pytest` passes locally
- [ ] New/changed behavior has tests
- [ ] `README.md` / `ARCHITECTURE.md` updated if you changed public behavior
- [ ] No secrets, API keys, or customer data in commits or fixtures

## Reporting security issues

Do not open a public GitHub issue for a security vulnerability in NEXUS
itself. See `SECURITY.md` for the disclosure process.

## Adding a new detection module

If you're proposing a larger module (e.g. a real ML-based detector, a new
data source integration), open an issue first describing the approach —
particularly how it stays explainable and testable — before submitting a
large PR.
