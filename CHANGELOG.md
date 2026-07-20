# Changelog

All notable changes to andas. Versions are git tags; binaries are on the
[releases page](https://github.com/malandas/andas/releases).

## v1.0.0
- First stable release. andas is strictly read-only: it scans and reports,
  and never edits code, rotates keys, or opens PRs.
- Integration tests for the CLI wiring and the git-history scanner; the repo
  now has CI (vet + test + a self-scan gate).

## v0.9.0
- Exposure timeline (how long a secret has been leaked) via git blame.
- Attack-path narrative chaining live secrets, reachable vulns, and history leaks.
- Live validators for OpenAI and Twilio.
- `--markdown` PR-comment report; exposure + attack path in the HTML report.

## v0.8.0
- Blast-radius scoring: live secrets are ranked by identity and permissions
  (GitHub/GitLab/SendGrid scopes, AWS ARN, Stripe/npm privilege).

## v0.7.0
- `andas hook` git pre-commit guard; `.andasignore` path filtering.

## v0.6.0
- Unit-test suite over the real-risk core.

## v0.5.0
- Entropy detection of unknown/custom secrets; baseline workflow.

## v0.4.0
- Git-history secret scanning; HTML and SARIF reports; remediation lines.

## v0.3.0
- Function-level used-symbol evidence; Yarn Berry; AWS/npm/SendGrid/Telegram validators.

## v0.2.x
- npm/Yarn dependency scanning with import-level reachability (OSV.dev).

## v0.1.0
- Secret scanning with live validation and the real-risk model.
