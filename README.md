# andas

[![ci](https://github.com/malandas/andas/actions/workflows/ci.yml/badge.svg)](https://github.com/malandas/andas/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/malandas/andas)](https://github.com/malandas/andas/releases/latest)
[![license](https://img.shields.io/github/license/malandas/andas)](LICENSE)

Most security scanners bury you in alerts. `andas` answers the question they
don't: **is this risk actually real for *your* project, or is it noise?**

- A detected secret is only an emergency if it's **still live**. `andas` asks the
  provider — safely, read-only — and demotes dead credentials out of your way.
- A CVE in an npm dependency only matters if that package is **reachable** from
  your app's own code. `andas` traces your imports and demotes vulnerabilities
  in packages nothing imports, and in dev dependencies that never ship.

One dependency-free binary scans it all — **secrets, dependencies, your code,
your config, container images, and licenses** — and ranks by what's *actually*
exploitable, not what merely matches a pattern.

```text
$ andas scan .

  CRITICAL  Stripe Secret Key            src/pay.js:12   sk_l******cd
            â² VERIFIED LIVE — rotate this credential now
            ð can access: full account access
            â± exposed ~63 days (since 2025-05-19)
  CRITICAL  lodash — Prototype Pollution  package.json    lodash@4.17.11
            â² reachable from your app code
            â³ your code uses: merge, template
  INFO      GitHub Token (old)           src/legacy.js:3 ghp_******yz
            â¼ verified dead — demoted out of the noise

  7 real risk(s), 41 demoted to noise, 48 total
```

**That last line is the whole point:** 48 findings, but only 7 that can hurt you.

### What it checks

| | |
|---|---|
| ð **Secrets** | 23 patterns, **live-validated** against 17 providers + blast-radius scoring |
| ð¦ **Dependencies** | 6 ecosystems (npm, PyPI, Go, RubyGems, crates, Packagist) with **reachability** |
| ð» **Your code (SAST)** | **27 CWE classes** with intra-procedural taint tracking |
| ðï¸ **Config (IaC)** | Dockerfile Â· compose Â· GitHub Actions Â· Terraform Â· Kubernetes |
| ð³ **Container images** | OS packages (Debian/Ubuntu/Alpine) via `andas image` |
| ð **Licenses & SBOM** | copyleft/unknown-license flags Â· CycloneDX SBOM |

Dependency-free Â· read-only Â· Linux, macOS, Windows.

## Install

Grab a prebuilt binary from the [latest release](https://github.com/malandas/andas/releases/latest):

```sh
# macOS (Apple Silicon) example
curl -sSL -o andas https://github.com/malandas/andas/releases/latest/download/andas-darwin-arm64
chmod +x andas && ./andas version
```

With a Go toolchain:

```sh
go install github.com/malandas/andas@latest
# or from a clone:
go build -o andas .
```

## Usage

```sh
andas scan                    # scan the current directory
andas scan ./myproject        # scan a specific path
andas scan . --history        # also sweep git history for removed secrets
andas scan . --html out.html  # write a shareable HTML report
andas scan . --sarif r.sarif  # SARIF for CI / GitHub code scanning
andas scan . --json           # machine-readable output
andas scan . --offline        # no network calls at all
andas image myimg.tar         # scan a docker-saved image for vulnerable OS packages
andas surface .               # map HTTP endpoints & auth gaps (authorised assessment)
andas pentest .               # recon report: endpoints -> vulns + live creds
```

### Adopting on a repo that already has debt

```sh
andas scan . --baseline andas-baseline.json --update-baseline  # accept today's state
andas scan . --baseline andas-baseline.json                    # now only NEW risk fails CI
```

### Guard your commits

```sh
andas hook install     # installs a git pre-commit hook
andas hook status      # is it installed?
andas hook uninstall   # remove it
```

The hook runs `andas scan . --offline --since HEAD --fail-on medium` before every commit, so
a hardcoded secret is caught **before it enters history** — which is the leak
you can never fully undo. Override a false positive with `git commit --no-verify`.

### Ignoring paths

Drop an `.andasignore` in the repo root, one pattern per line (like
`.gitignore`): a path segment (`testdata`, `src/generated`), a glob (`*.min.js`),
or a `#` comment. Matching files are skipped by the working-tree scanners.

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--history` | off | Also scan the full git history for secrets removed from HEAD. |
| `--licenses` | off | Flag dependency licenses with legal obligations (needs installed deps). |
| `--since <ref>` | — | Only report findings in files changed since a git ref (fast PR scans). |
| `--baseline <path>` | — | Suppress findings recorded in this baseline file. |
| `--update-baseline` | off | Accept all current findings into `--baseline`, then exit. |
| `--no-entropy` | off | Disable entropy-based detection of unknown/custom secrets. |
| `--html <path>` | — | Write a self-contained HTML report. |
| `--sarif <path>` | — | Write a SARIF 2.1.0 report for CI / code scanning. |
| `--markdown <path>` | — | Write a PR-comment-style Markdown report. |
| `--sbom <path>` | — | Write a CycloneDX SBOM of all resolved dependencies. |
| `--no-validate` | off | Skip live validation of secrets. |
| `--offline` | off | Make no network calls at all (no validation, no OSV lookup). |
| `--json` | off | Emit JSON instead of the table. |
| `--no-color` | off | Disable coloured output. |
| `--timeout` | `8` | Per-validation network timeout (seconds). |
| `--fail-on` | `high` | Exit non-zero when real risk reaches this level. |

Exit code is non-zero when the **real** risk reaches `--fail-on`, so you can
gate a CI pipeline on live secrets while ignoring dead ones.

## How the real-risk score works

Every finding carries two levels:

- **Severity** — the theoretical/pattern-based level (what other tools give you).
- **Real risk** — after `andas`'s context check:
  - secret **verified live** â promoted to `CRITICAL`
  - secret **verified dead** â demoted to `INFO` (this is the noise we remove)
  - couldn't verify â keeps its theoretical severity

## What live validation actually does

For each secret type with a validator, `andas` sends **one read-only request to
that credential's own provider** (e.g. `GET api.github.com/user`) and reads the
HTTP status: `2xx` = live, `401/403` = dead. It never writes, and never sends a
secret anywhere except its legitimate provider. Use `--no-validate` for a fully
offline scan.

Validators today: GitHub (PATs + OAuth/App tokens), GitLab, Slack, Stripe, npm,
SendGrid, Telegram, OpenAI, DigitalOcean, Mailgun, Figma, Notion, Airtable, Postman, Dropbox, and
the paired ones —
**AWS** (an `AKIA…` key + a nearby secret, proven with a signed STS
`GetCallerIdentity`) and **Twilio** (an `AC…` SID + a nearby auth token).
Detection-only: Google, private-key blocks.

**andas is strictly read-only.** It scans files and makes only read-only
requests to a credential's own provider — it never edits your code, rotates
keys, or opens PRs. It shows you the risk and the fix; the action stays with you.

Beyond these known shapes, an **entropy heuristic** catches custom/internal
secrets: a high-randomness value assigned to a secret-looking name (`*token*`,
`*apiKey*`, `*password*`, …). These are unverifiable, so they report as MEDIUM —
and if one is a false positive, `--baseline` silences it for good.

## Blast radius — how much can a live secret actually do?

A live secret is critical, but a live *admin* secret is a five-alarm fire.
Because andas is already talking to the provider, it reads back the credential's
**identity and permissions** and flags the dangerous ones:

```
CRITICAL  GitHub Personal Access Token
          src/ci/deploy.js:8   ghp_••••••yz
          â² VERIFIED LIVE — rotate this credential now
          identity: octocat
          ð can access: repo, admin:org, workflow
          â  HIGH-PRIVILEGE credential — maximum blast radius
```

- **GitHub** â OAuth scopes (`repo`, `admin:org`, `delete_repo`, …)
- **GitLab** â personal-access-token scopes (`api`, `sudo`, …)
- **SendGrid** â API-key scopes (`mail.send`, admin scopes)
- **AWS** â the identity ARN and account, root/admin flagged
- **Stripe / npm** â full-access keys flagged as privileged

High-privilege live secrets sort to the very top of the report — same severity,
bigger blast radius.

## Exposure timeline & attack path

Two more read-only signals that turn a list of findings into a real picture:

- **Exposure timeline** — from git blame (and commit dates for history leaks),
  andas tells you *how long* a secret has been exposed: `â± exposed ~47 days
  (since 2025-11-08)`. A key leaked months ago is a different emergency from one
  added today.
- **Attack path** — andas narrates how the confirmed findings chain together:

  ```
  â attack path
     • A live, high-privilege AWS (arn:…:root) is exposed — an attacker gains account access.
     • Multiple live credentials are exposed together (AWS, GitHub) — one leaked repo hands an attacker all of them.
     • A credential removed from the code is still live in git history — deleting the line never rotated the key.
  ```

  Every line is grounded in something andas actually verified — never invented risk.

## Dependency scanning — many languages

`andas` scans dependency manifests across ecosystems and cross-references every
package against [OSV.dev](https://osv.dev):

| Language | Manifest | Reachability |
|----------|----------|--------------|
| JavaScript / TypeScript | `package.json` + `package-lock.json` / `yarn.lock` | â import-level + used symbols |
| Python | `requirements.txt` (pinned) | â import-level |
| Go | `go.mod` | â import-level |
| Ruby | `Gemfile.lock` | â import-level |
| Rust | `Cargo.lock` | â import-level |
| PHP | `composer.lock` | â import-level |

**All six ecosystems** now get the same real-risk filter: andas parses your
source and **demotes a vulnerability in any package your code never imports**.
For all six languages, andas also reports which functions of a vulnerable package your code actually calls (`â³ your code uses: safe_load`). Each language.s import mechanism is handled honestly — Python resolves
distributionâmodule aliases (`PyYAML`â`yaml`); Go matches a module or any of its
subpackages; Rust maps Cargo hyphens to `use` underscores; PHP reads each
package's PSR-4 namespace from `composer.lock` and matches `use` statements; Ruby
falls back to treating **all** gems as reachable when it sees `Bundler.require`
(which auto-loads everything), so a used gem is never wrongly cleared.

## Reachability, in depth (JS/TS)

For a project with a `package.json`, `andas` also:

1. Reads `package.json` plus a lockfile — `package-lock.json` (npm) or
   `yarn.lock` (Yarn v1 **and** Berry/v2+) — to resolve the full dependency tree
   with exact versions. With no lockfile it falls back to direct dependencies.
2. Queries [OSV.dev](https://osv.dev) (free, no API key) for known
   vulnerabilities in each package.
3. Parses your `.js/.jsx/.ts/.tsx` source to see which packages you actually
   import, then walks the graph to compute what's **reachable**. A vulnerable
   package outside that set — an unused transitive dep, or a dev-only tool that
   never ships in your React Native bundle — is demoted to `LOW`.

Reachability is at the **import level** (is the package reached at all). As a
first step toward function-level reachability, `andas` also reports **which
exports of a vulnerable package your code actually uses** (`â³ your code uses:
merge, template`) — evidence for triage. It deliberately does **not** downgrade
on this signal: mapping an advisory to exact functions is unreliable, and a
false "safe" is worse than a false alarm.

## Git-history secret scanning (`--history`)

The sharpest edge. A credential deleted from your latest commit still lives in
git history — and history is public the moment the repo is. With `--history`,
andas sweeps **every blob across all branches and commits**, and — because it
validates live — reports the case that actually matters:

```
CRITICAL  AWS Access Key ID (in git history)
          git history @ 4f1a9c2 (Sara N., 2025-11-08)   AKIA••••••7Q
          â² removed from HEAD but still recoverable — AWS accepted the key pair — LIVE
          â fix: Deactivate the key in IAM â Security credentials, then create a fresh pair.
```

Secrets still in the working tree are left to the normal file scan; `--history`
reports only the ones that were **removed but never rotated**.

## Static analysis of your own code (SAST)

Beyond secrets and dependencies, `andas` scans your own source for dangerous
patterns — code injection (`eval`), OS command execution, unsafe deserialization, path
traversal, SSRF, weak crypto (MD5/SHA1, insecure randomness), XXE, template
injection (SSTI), open redirect, NoSQL injection, disabled TLS, XSS, and SQL
injection, plus broken JWT verification, insecure cookies, hardcoded crypto keys,
disabled CSRF, world-writable files, weak TLS, LDAP/XPath injection, prototype
pollution, mass assignment, regex-from-input (ReDoS), and Node-specific sinks
(vm escape, dynamic require, shell spawn) — 27 CWE classes
across JS/TS, Python, Ruby, PHP, and Go, each
tagged with its CWE. The rules are tight and high-signal, and every finding
notes whether **user-controlled input reaches it** — either directly on the line
(`req.query`, `$_GET`, `request.args`, …) or through a variable assigned from
user input earlier in the same function. andas follows that with a light
**intra-procedural taint tracker**, so a dangerous sink is flagged as
user-reachable even when the source is several lines above it. It only ever
raises a finding's confidence, never lowers it. Comment lines and minified/generated code are skipped to keep false positives down.

## Infrastructure & CI config (IaC)

`andas` also scans the config files every repo ships with:

- **Dockerfiles** — running as `root`, `:latest` base images, `ADD` from a URL,
  `curl ... | bash`, `chmod 777`.
- **docker-compose** — `privileged: true`, the Docker socket mounted into a
  service, host networking.
- **GitHub Actions** — script injection via `${{ github.event.* }}` in `run:`, `pull_request_target`, third-party actions pinned to a moving branch.
- **Terraform** — security groups open to `0.0.0.0/0`, public bucket ACLs, encryption disabled, hardcoded credentials.
- **Kubernetes** — privileged containers, host namespaces, run-as-root, privilege escalation allowed.

## Reports & CI

- `--html <path>` — a self-contained, theme-aware HTML report you can share.
- `--sarif <path>` — SARIF 2.1.0; the level of each result is driven by **real
  risk**, so a dead secret lands as a note and a live one as an error. Upload it
  with `github/codeql-action/upload-sarif` to populate the Security tab.
- `--markdown <path>` — a compact, PR-comment-style summary. andas only writes
  the file; posting it (if you want) is your CI's job — andas stays read-only.
- Every finding carries a concrete **fix** line (rotation link, upgrade target).

A ready-to-use workflow is in [`examples/github-workflow.yml`](examples/github-workflow.yml).

## License compliance

`andas scan . --licenses` reads the licenses of your **installed** dependencies
(`node_modules` for npm, `*.dist-info` for Python) and flags the ones with legal
obligations — **strong copyleft** (GPL/AGPL) and **missing/unknown** licenses.
It auto-detects whether your project is proprietary (a `private` or `UNLICENSED`
package.json) or open-source and scores accordingly: an AGPL dependency is a
`HIGH` obligation for a closed product but merely informational for an OSS one.
Permissive licenses (MIT, BSD, Apache) are treated as noise.

## Attack-surface map (for authorised assessment)

For a penetration tester or bug-bounty researcher handed a codebase, `andas
surface` maps the HTTP endpoints it exposes — across Express, Flask/FastAPI,
Django, Rails, Gin, and Laravel — and surfaces the ones worth testing first:
**no visible authentication** and **taking user input**.

```text
POST   /api/exec    ⚠ no-auth ⌨ input   routes.js:5   Express
GET    /admin       🔒 auth              routes.js:4   Express
```

It reads source only — it never touches a live target. Use it to plan testing
on systems you are **authorised** to assess.

## SBOM (Software Bill of Materials)

`andas scan . --sbom bom.json` writes a **CycloneDX 1.5** SBOM of every
dependency it resolves across all six ecosystems — with correct package URLs
(`pkg:npm/lodash@4.17.11`, `pkg:pypi/Django@2.2.0`, `pkg:golang/…`, …). Since
andas already resolves the full graph to scan it, the SBOM is the same data in
the standard format vendors, dashboards, and regulators expect.

## Configuration

Drop an optional `.andas.yml` in the repo root to tune a scan without flags:

```yaml
fail-on: critical      # default gate level
disable:               # silence specific rules by id
  - docker-latest-tag
  - gha-unpinned-action
ignore:                # extra ignore globs (merged with .andasignore)
  - testdata
```

Scanners run **concurrently**, so on a large repo the total scan time is roughly the slowest single scanner rather than the sum of all of them.

## Development

```sh
go build -o andas .   # build
go test ./...         # run the test suite
go vet ./...          # static checks
```

The suite covers the security-critical logic directly: the real-risk decision
table, entropy precision (it must catch real secrets and reject placeholders),
the npm/Yarn (v1 + Berry) lockfile parser, the reachability BFS, the blast-radius
scope parsers, the baseline round-trip (which must never persist raw secret
material), plus end-to-end tests of the CLI wiring and the git-history scanner.
CI runs `vet` + `test` and has andas scan its own source on every push.

See [CHANGELOG.md](CHANGELOG.md) for release history, [ARCHITECTURE.md](ARCHITECTURE.md) for how it works inside, and [CONTRIBUTING.md](CONTRIBUTING.md) to get involved — new secret validators and SAST rules make great first PRs.

## Status

`v1.8.0` (SAST now follows a light intra-procedural taint flow) — **five scanners on one real-risk core: secrets (17 live validators), dependencies (6 ecosystems, reachability + function-level), git history, SAST, and IaC/CI config** (Dockerfile, docker-compose, GitHub Actions), on one real-risk core with blast-radius
scoring, exposure timeline, attack-path narrative, entropy detection, baseline,
a pre-commit guard, four report formats, and a 48-test suite. Strictly
read-only:

| Scanner | Detects | Context that separates signal from noise |
|---------|---------|------------------------------------------|
| **secrets** | 12 credential types | live validation across 8 providers (incl. signed AWS STS) |
| **deps** | npm/Yarn vulns (v1 & Berry) | import reachability + which vulnerable functions your code calls |
| **git-history** | secrets removed from HEAD | still-in-history **and** still-live |

Outputs: terminal, JSON, HTML, SARIF — each with remediation.

## License

MIT — see [LICENSE](LICENSE).
