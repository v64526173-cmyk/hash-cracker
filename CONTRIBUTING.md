# Contributing

Thanks for considering a contribution! This started as a portfolio/learning
project, so contributions that improve its teaching value are especially
welcome.

## Getting set up

```bash
git clone https://github.com/YOUR_USERNAME/hash-cracker.git
cd hash-cracker
pip install -r requirements.txt
pytest tests/ -v
```

## Guidelines

- Keep the standard-library-only runtime dependency policy — the point of
  this project is to be runnable anywhere with no setup friction.
- Add or update tests in `tests/` for any behavior change.
- Favor clear explanatory comments/docstrings over clever one-liners —
  this is an educational project first.
- Run `pytest tests/ -v` and make sure CI (`.github/workflows/ci.yml`)
  passes before opening a PR.

## Ideas for contributions

See the Roadmap section in `README.md` for concrete feature ideas (rule-based
mangling, resumable brute-force jobs, JSON output, etc).
