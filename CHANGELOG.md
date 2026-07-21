# Changelog

All notable changes to andas. Versions are git tags; binaries are on the
[releases page](https://github.com/malandas/andas/releases).

## v1.16.0
- A coloured ASCII banner on the welcome/help screen (`andas`, `andas help`).
  Shown only on an interactive terminal — never during a scan, so JSON/CI output
  stays clean; respects NO_COLOR and non-TTY output.

## v1.15.0
- SAST expanded from 22 to 27 CWE classes: added LDAP injection (CWE-90), XPath
  injection (CWE-643), prototype pollution (CWE-1321), mass assignment
  (CWE-915), and regex-from-user-input / ReDoS (CWE-1333).
- Fewer false positives: SAST now skips comment lines and minified/generated
  lines (over 1000 chars), so a dangerous pattern in commented-out code or a
  bundled file no longer fires.

## v1.14.0
- SAST expanded from 15 to 22 CWE classes: added broken JWT verification
  (CWE-347), insecure cookie flags (CWE-614), hardcoded cryptographic keys
  (CWE-321), disabled CSRF protection (CWE-352), world-writable file modes
  (CWE-732), and weak SSL/TLS protocol versions (CWE-326), across the five
  languages.

## v1.13.0
- SAST coverage expanded from 6 to 15 CWE classes: added path traversal
  (CWE-22), SSRF (CWE-918), weak crypto — MD5/SHA1 (CWE-328) and insecure
  randomness (CWE-338), XXE (CWE-611), template injection / SSTI (CWE-1336),
  open redirect (CWE-601), and NoSQL injection (CWE-943), across JS/TS, Python,
  Ruby, PHP, and Go. All flow through the same taint tracker.

## v1.12.0
- Differential scanning: `andas scan . --since <ref>` reports only findings in
  files changed versus a git ref (branch, HEAD~1, ...), including new untracked
  files. Turns a full-repo scan into a fast PR/pre-commit gate that fails on
  newly introduced risk without re-flagging existing debt. The pre-commit hook
  now uses --since HEAD.

## v1.11.0
- License compliance (`--licenses`): reads installed dependency licenses
  (node_modules, *.dist-info) and flags strong copyleft (GPL/AGPL) and
  missing/unknown licenses. Auto-detects proprietary vs OSS projects and scores
  copyleft accordingly; permissive licenses are treated as noise.

## v1.10.0
- SBOM generation: `andas scan . --sbom bom.json` writes a CycloneDX 1.5
  Software Bill of Materials of every resolved dependency across all six
  ecosystems, with correct package URLs (purls). Reuses the graph andas already
  builds to scan.

## v1.9.0
- Scanners now run concurrently — on a large repo the scan takes about as long
  as its slowest single scanner instead of the sum. OSV detail lookups are
  fetched in parallel too.
- Container image scanning: `andas image <image.tar>` reads a `docker save`
  tarball, extracts the OS package database (dpkg/apk), and reports vulnerable
  packages via OSV (Debian/Ubuntu/Alpine, versioned ecosystems).
- IaC scanner extended to Terraform (open security groups, public ACLs,
  disabled encryption, hardcoded creds) and Kubernetes (privileged, host
  namespaces, run-as-root, privilege escalation).
- Optional .andas.yml config: disable rules, add ignore globs, set fail-on.

## v1.8.0
- SAST gains a light intra-procedural taint tracker: a variable assigned from a
  user-input source (request.args, $_GET, ...) taints later uses of it within
  the same function, so a dangerous sink is flagged as user-reachable even when
  the source is several lines away. Resets at function boundaries; only raises a
  finding's confidence, never lowers it.

## v1.7.0
- New IaC scanner: flags insecure infrastructure/CI config in the files every
  repo ships — Dockerfiles (root user, :latest, ADD from URL, curl|bash, chmod
  777), docker-compose (privileged, docker.sock mount, host network), and
  GitHub Actions workflows (script injection via github.event.* in run:,
  pull_request_target, third-party actions pinned to a moving branch).

## v1.6.0
- New SAST scanner: statically flags dangerous patterns in your own source —
  code injection (eval/new Function/exec), OS command execution, unsafe
  deserialization (pickle/Marshal/unserialize/yaml.load), disabled TLS
  verification, XSS sinks, and interpolated SQL — across JS/TS, Python, Ruby,
  PHP, and Go, tagged with CWE ids. Each finding notes whether user-controlled
  input appears on the same line (the cheap reachability signal). Tight,
  high-signal rules; pattern-based, not full taint analysis.

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
