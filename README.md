# naqi

**نَقِّ مخرجاتك الأمنية من الضجيج.** — *Sift real security risk from the noise.*

Most security scanners bury you in alerts. `naqi` answers the question they
don't: **is this risk actually real for *your* project, or is it noise?**

- A detected secret is only an emergency if it's **still live**. `naqi` asks the
  provider — safely, read-only — and demotes dead credentials out of your way.
- (Roadmap) A CVE in a dependency only matters if the vulnerable code is
  **reachable** from your app. `naqi` will trace that too.

One command. One dependency-free binary. Linux, macOS, Windows.

## Install

Download the binary for your OS from `dist/`, or build from source:

```sh
go build -o naqi .
```

## Usage

```sh
naqi scan               # scan the current directory
naqi scan ./myproject   # scan a specific path
naqi scan . --json      # machine-readable output for CI
naqi scan . --no-validate   # offline: detect only, no network calls
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--no-validate` | off | Detect only; make no network calls. |
| `--json` | off | Emit JSON instead of the table. |
| `--no-color` | off | Disable coloured output. |
| `--timeout` | `8` | Per-validation network timeout (seconds). |
| `--fail-on` | `high` | Exit non-zero when real risk reaches this level. |

Exit code is non-zero when the **real** risk reaches `--fail-on`, so you can
gate a CI pipeline on live secrets while ignoring dead ones.

## How the real-risk score works

Every finding carries two levels:

- **Severity** — the theoretical/pattern-based level (what other tools give you).
- **Real risk** — after `naqi`'s context check:
  - secret **verified live** → promoted to `CRITICAL`
  - secret **verified dead** → demoted to `INFO` (this is the noise we remove)
  - couldn't verify → keeps its theoretical severity

## What live validation actually does

For each secret type with a validator, `naqi` sends **one read-only request to
that credential's own provider** (e.g. `GET api.github.com/user`) and reads the
HTTP status: `2xx` = live, `401/403` = dead. It never writes, and never sends a
secret anywhere except its legitimate provider. Use `--no-validate` for a fully
offline scan.

Validators today: GitHub, GitLab, Slack, Stripe. Detection-only (no validator
yet): AWS, Google, OpenAI, private-key blocks.

## Status

`v0.1.0` — secret scanning + live validation. Next up: dependency-vulnerability
scanning with **reachability analysis**, sharing this same real-risk core.
