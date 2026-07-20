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

`andas` finds three kinds of real risk: leaked **secrets** (is it still live?), vulnerable **dependencies** (does your code reach it?), and dangerous **code** patterns in your own source (SAST). One dependency-free binary. Linux, macOS, Windows.

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

The hook runs `andas scan . --offline --fail-on medium` before every commit, so
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
| `--baseline <path>` | — | Suppress findings recorded in this baseline file. |
| `--update-baseline` | off | Accept all current findings into `--baseline`, then exit. |
| `--no-entropy` | off | Disable entropy-based detection of unknown/custom secrets. |
| `--html <path>` | — | Write a self-contained HTML report. |
| `--sarif <path>` | — | Write a SARIF 2.1.0 report for CI / code scanning. |
| `--markdown <path>` | — | Write a PR-comment-style Markdown report. |
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
  - secret **verified live** → promoted to `CRITICAL`
  - secret **verified dead** → demoted to `INFO` (this is the noise we remove)
  - couldn't verify → keeps its theoretical severity

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
          ▲ VERIFIED LIVE — rotate this credential now
          identity: octocat
          🔓 can access: repo, admin:org, workflow
          ⚠ HIGH-PRIVILEGE credential — maximum blast radius
```

- **GitHub** → OAuth scopes (`repo`, `admin:org`, `delete_repo`, …)
- **GitLab** → personal-access-token scopes (`api`, `sudo`, …)
- **SendGrid** → API-key scopes (`mail.send`, admin scopes)
- **AWS** → the identity ARN and account, root/admin flagged
- **Stripe / npm** → full-access keys flagged as privileged

High-privilege live secrets sort to the very top of the report — same severity,
bigger blast radius.

## Exposure timeline & attack path

Two more read-only signals that turn a list of findings into a real picture:

- **Exposure timeline** — from git blame (and commit dates for history leaks),
  andas tells you *how long* a secret has been exposed: `⏱ exposed ~47 days
  (since 2025-11-08)`. A key leaked months ago is a different emergency from one
  added today.
- **Attack path** — andas narrates how the confirmed findings chain together:

  ```
  ⚔ attack path
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
| JavaScript / TypeScript | `package.json` + `package-lock.json` / `yarn.lock` | ✅ import-level + used symbols |
| Python | `requirements.txt` (pinned) | ✅ import-level |
| Go | `go.mod` | ✅ import-level |
| Ruby | `Gemfile.lock` | ✅ import-level |
| Rust | `Cargo.lock` | ✅ import-level |
| PHP | `composer.lock` | ✅ import-level |

**All six ecosystems** now get the same real-risk filter: andas parses your
source and **demotes a vulnerability in any package your code never imports**.
For all six languages, andas also reports which functions of a vulnerable package your code actually calls (`↳ your code uses: safe_load`). Each language.s import mechanism is handled honestly — Python resolves
distribution→module aliases (`PyYAML`→`yaml`); Go matches a module or any of its
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
exports of a vulnerable package your code actually uses** (`↳ your code uses:
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
          ▲ removed from HEAD but still recoverable — AWS accepted the key pair — LIVE
          → fix: Deactivate the key in IAM → Security credentials, then create a fresh pair.
```

Secrets still in the working tree are left to the normal file scan; `--history`
reports only the ones that were **removed but never rotated**.

## Static analysis of your own code (SAST)

Beyond secrets and dependencies, `andas` scans your own source for dangerous
patterns — code injection (`eval`), OS command execution, unsafe deserialization
(`pickle.loads`, `unserialize`), disabled TLS verification, XSS sinks, and SQL
built by string interpolation — across JS/TS, Python, Ruby, PHP, and Go, each
tagged with its CWE. The rules are tight and high-signal, and every finding
notes whether **user-controlled input appears on the same line** (`req.query`,
`$_GET`, `request.args`, …) — the cheap signal that a dangerous sink is actually
reachable by an attacker. Detection is pattern-based, not full taint analysis.

## Reports & CI

- `--html <path>` — a self-contained, theme-aware HTML report you can share.
- `--sarif <path>` — SARIF 2.1.0; the level of each result is driven by **real
  risk**, so a dead secret lands as a note and a live one as an error. Upload it
  with `github/codeql-action/upload-sarif` to populate the Security tab.
- `--markdown <path>` — a compact, PR-comment-style summary. andas only writes
  the file; posting it (if you want) is your CI's job — andas stays read-only.
- Every finding carries a concrete **fix** line (rotation link, upgrade target).

A ready-to-use workflow is in [`examples/github-workflow.yml`](examples/github-workflow.yml).

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

See [CHANGELOG.md](CHANGELOG.md) for the release history.

## Status

`v1.6.0` — **four scanners on one real-risk core: secrets (17 live validators), dependencies (6 ecosystems, reachability + function-level), git history, and SAST of your own code** (JS/TS, Python, Ruby, PHP, Go), on one real-risk core with blast-radius
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
