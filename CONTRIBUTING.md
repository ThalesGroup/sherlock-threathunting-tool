# Contributing guidelines

Thank you for considering a contribution to SHERLOCK.

## How to contribute

- **Bugs and ideas** - open a GitHub issue describing the behaviour observed, the
  behaviour expected, and how to reproduce it. For anything security-related, do **not**
  open a public issue: follow [SECURITY.md](SECURITY.md).
- **Code** - fork the repository, create a branch, and open a pull request against
  `main`. Keep pull requests focused: one change per PR.

## Ground rules

SHERLOCK is built around guarantees that are enforced in code, not in prompts
(see the README). Pull requests must not weaken them:

- **No write tool for the agent.** Never add a remediation, isolation, account or rule
  action - not even behind a flag.
- **Every outbound call goes through `src/middleware`.** No direct network calls
  elsewhere, and guard-rails (caps, masking, rate limits) live in that layer only.
- **No unsourced IOC.** An indicator without a citable source must remain impossible.
- **Untrusted content stays data.** SIEM results and web pages are wrapped and never
  interpreted as instructions.

## Development setup

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
cd web && npm install
```

## Pull request checklist

- [ ] `.venv/bin/python -m pytest` - the full suite passes (guard-rail tests first).
- [ ] `ruff check .` - lint clean.
- [ ] `cd web && npx tsc --noEmit && npm run build && npx vitest run` - frontend clean.
- [ ] New behaviour is covered by tests; guard-rail changes are covered in priority.
- [ ] Code style matches the surroundings: type hints everywhere, no superfluous
      comments, English identifiers and messages.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), like the rest of the project.
