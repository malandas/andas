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
andas scan               # scan the current directory
andas scan ./myproject   # scan a specific path
andas scan . --json      # machine-readable output for CI
andas scan . --no-validate   # offline: detect only, no network calls
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
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

Validators today: GitHub, GitLab, Slack, Stripe. Detection-only (no validator
yet): AWS, Google, OpenAI, private-key blocks.

## Dependency scanning with reachability (JS/TS)

For a project with a `package.json`, `andas` also:

1. Reads `package.json` + `package-lock.json` to resolve the full dependency
   tree with exact versions.
2. Queries [OSV.dev](https://osv.dev) (free, no API key) for known
   vulnerabilities in each package.
3. Parses your `.js/.jsx/.ts/.tsx` source to see which packages you actually
   import, then walks the graph to compute what's **reachable**. A vulnerable
   package outside that set — an unused transitive dep, or a dev-only tool that
   never ships in your React Native bundle — is demoted to `LOW`.

Reachability today is at the **import level** (is the package reached at all).
Function-level reachability (is the specific vulnerable API called) is the next
step.

## Status

`v0.2.0` — secret scanning with live validation **+** npm dependency scanning
with import-level reachability. Both share one real-risk core and one report.
