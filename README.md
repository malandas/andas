# andas

**نَقِّ مخرجاتك الأمنية من الضجيج.** — *Sift real security risk from the noise.*

Most security scanners bury you in alerts. `andas` answers the question they
don't: **is this risk actually real for *your* project, or is it noise?**

- A detected secret is only an emergency if it's **still live**. `andas` asks the
  provider — safely, read-only — and demotes dead credentials out of your way.
- A CVE in an npm dependency only matters if that package is **reachable** from
  your app's own code. `andas` traces your imports and demotes vulnerabilities
  in packages nothing imports, and in dev dependencies that never ship.

One command. One dependency-free binary. Linux, macOS, Windows.

## Install

Download the binary for your OS from `dist/`, or build from source:

```sh
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

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--history` | off | Also scan the full git history for secrets removed from HEAD. |
| `--baseline <path>` | — | Suppress findings recorded in this baseline file. |
| `--update-baseline` | off | Accept all current findings into `--baseline`, then exit. |
| `--no-entropy` | off | Disable entropy-based detection of unknown/custom secrets. |
| `--html <path>` | — | Write a self-contained HTML report. |
| `--sarif <path>` | — | Write a SARIF 2.1.0 report for CI / code scanning. |
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

Validators today: GitHub, GitLab, Slack, Stripe, npm, SendGrid, Telegram, and
**AWS** (which pairs a detected `AKIA…` access key ID with a nearby secret and
proves the pair with a signed, read-only STS `GetCallerIdentity` call).
Detection-only (no validator yet): Google, OpenAI, private-key blocks.

Beyond these known shapes, an **entropy heuristic** catches custom/internal
secrets: a high-randomness value assigned to a secret-looking name (`*token*`,
`*apiKey*`, `*password*`, …). These are unverifiable, so they report as MEDIUM —
and if one is a false positive, `--baseline` silences it for good.

## Dependency scanning with reachability (JS/TS)

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

## Reports & CI

- `--html <path>` — a self-contained, theme-aware HTML report you can share.
- `--sarif <path>` — SARIF 2.1.0; the level of each result is driven by **real
  risk**, so a dead secret lands as a note and a live one as an error. Upload it
  with `github/codeql-action/upload-sarif` to populate the Security tab.
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
the npm/Yarn (v1 + Berry) lockfile parser, the reachability BFS, and the
baseline round-trip (which must never persist raw secret material). Network
validation, git plumbing, and file walking are covered by integration runs.

## Status

`v0.6.0` — three scanners on one real-risk core, entropy detection of unknown
secrets, a baseline workflow for repos with existing debt, and a unit-test suite
guarding the core logic:

| Scanner | Detects | Context that separates signal from noise |
|---------|---------|------------------------------------------|
| **secrets** | 12 credential types | live validation across 8 providers (incl. signed AWS STS) |
| **deps** | npm/Yarn vulns (v1 & Berry) | import reachability + which vulnerable functions your code calls |
| **git-history** | secrets removed from HEAD | still-in-history **and** still-live |

Outputs: terminal, JSON, HTML, SARIF — each with remediation.
