# Changelog

All notable changes to andas. Versions are git tags; binaries are on the
[releases page](https://github.com/malandas/andas/releases).

## v1.5.0
- Function-level evidence completed for all six ecosystems: added Ruby
  (gem->constant, Const::x / Const.x), Rust (crate::Item), and PHP (use
  Ns\\Class, mapped via composer.lock PSR-4). Evidence only.
- Two more live secret validators (Postman, Dropbox) plus detection for
  Shopify and PyPI tokens. 17 validators, 23 detection patterns.

## v1.4.0
- Function-level evidence extended to Python and Go: reachable vulnerable
  packages now show which of their exports your code actually calls
  (e.g. `your code uses: safe_load`), as JS already did. Evidence only.
- Three more live secret validators: Figma, Notion, Airtable (15 total).

## v1.3.0
- Import-level reachability completed for all six ecosystems: added Ruby, Rust,
  and PHP. Rust maps Cargo hyphens to `use` underscores; PHP reads PSR-4
  namespaces from composer.lock and matches `use` statements; Ruby treats all
  gems as reachable when it detects Bundler.require (auto-loads everything), so
  a used gem is never falsely demoted.

## v1.2.0
- Import-level reachability extended to Python and Go: a vulnerability in a
  package your source never imports is demoted, as it already was for npm.
  Python resolves distribution→module aliases (PyYAML→yaml, …); Go matches a
  module or any of its subpackages.

## v1.1.0
- Multi-language dependency scanning: Python (requirements.txt), Go (go.mod),
  Ruby (Gemfile.lock), Rust (Cargo.lock), PHP (composer.lock) — all via OSV.dev,
  alongside the existing npm/Yarn path (which keeps reachability analysis).
- Three more live secret validators: GitHub OAuth/App tokens, DigitalOcean, Mailgun.

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
