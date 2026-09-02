# Security Policy

SHERLOCK is a security tool: it queries SIEMs read-only, minimizes and pseudonymizes
data before any model call, and treats all external content as untrusted. Security
reports are taken seriously and handled with priority.

## Good practices to follow

:warning: **Never store credentials in source code or configuration files in the
repository.** API keys belong in the Configuration screen (encrypted store) or your
secret manager - never in `.env` files that get committed.
- Block sensitive data from being pushed with a pre-commit hook (git-secrets or similar).
- Audit for slipped secrets with dedicated tools.
- Use environment variables for secrets in CI/CD and a secret manager in production.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

Do **not** open a public issue. Use GitHub's private vulnerability reporting on this
repository ("Report a vulnerability" under the Security tab), or contact
**oss@thalesgroup.com**. Please include the affected component, reproduction steps and
impact. You can expect an acknowledgement within a few working days and updates as the
report is triaged.

## Disclosure policy

Coordinated disclosure: give the maintainers a reasonable window to investigate and
release a fix before any public disclosure. Reporters are credited in the release notes
unless they prefer otherwise.

## Security-related configuration

Settings that shape the security posture of a deployment:

- Deploy behind TLS (see `deploy/nginx-sherlock.conf`) and keep the API bound to
  localhost behind the reverse proxy.
- Keep `SHL_TI_OPEN_SEARCH=false` unless the wider egress has been reviewed and approved
  (`docs/web-search-security.md` describes the trade-off).
- Set `SHL_SECRET_STORE_KEY` to a generated value and keep it out of the repository;
  prefer a managed vault (`SHL_KEY_VAULT_URL`) in production.
- Set `SHL_CA_BUNDLE` when outbound traffic is TLS-inspected, rather than disabling
  verification.
- The semantic anonymization pass is fail-closed by default
  (`SHL_SEMANTIC_ANONYMIZATION_FAIL_CLOSED=true`); think twice before relaxing it.

## Known security gaps & future enhancements

- Authentication uses local admin-managed accounts; SSO/OIDC integration is left for
  adopters to wire in.
- Rate limiting on the login endpoint is basic; put the platform behind your usual
  access controls.
