# Architecture

andas is small and deliberately boring inside: a set of independent **scanners**
that each return `Finding`s, a shared **real-risk model** that ranks them, and a
few **reporters** that render the result. No framework, no dependencies.

## The flow

```
cmd/scan.go
  ├─ load .andas.yml + .andasignore
  ├─ run scanners concurrently ──► []finding.Finding
  │     secrets · deps · sast · iac · (git-history) · (licenses)
  ├─ filter: disabled rules, --baseline, --since
  └─ report: terminal · JSON · HTML · SARIF · Markdown · SBOM
```

`andas image <tar>` is a separate entry point (`cmd/image.go`) that scans a
container image's OS packages.

## Core packages

| Package | Responsibility |
|---------|----------------|
| `internal/finding` | The `Finding` type, the `Severity` scale, and **`RealRisk()`** — the one function that encodes the product: live secret → CRITICAL, dead → INFO, unreachable vuln → LOW. |
| `internal/scanner` | The `Scanner` interface (`Scan(root, opts) []Finding`), the shared file walker (`WalkText`), and `.andasignore` handling. |
| `internal/osv` | Shared OSV.dev client (batched query + concurrent detail fetch). |
| `internal/report` | Terminal, JSON, HTML, SARIF, Markdown renderers; attack-path narrative; baseline. |
| `internal/gitmeta` | Read-only git helpers (blame for exposure, changed-files for `--since`). |
| `internal/config`, `internal/sbom`, `internal/license` | `.andas.yml`, CycloneDX output, license classification. |

## The scanners

Each lives under `internal/scanner/<name>` and implements `scanner.Scanner`:

- **secrets** — regex rules + **live validation** (a read-only call to the
  provider tells us if a secret is still active; the result drives blast-radius
  scoring). Entropy detection catches unknown secrets.
- **deps** — parses lockfiles across six ecosystems, queries OSV, and computes
  **reachability** (does your code import the vulnerable package?) plus
  used-symbol evidence.
- **sast** — pattern rules over source, tagged with CWE, prioritised by a light
  intra-procedural **taint tracker** (`taint.go`).
- **iac** — Dockerfile / compose / GitHub Actions / Terraform / Kubernetes
  misconfigurations, matched by file kind.
- **githistory** — sweeps every git blob for secrets removed from HEAD.
- **licenses** — reads installed dependency licenses and flags copyleft/unknown.

## Adding a scanner

Implement the two-method `Scanner` interface, return `Finding`s with a `Kind`
and a `Severity`, and add it to the `scanners` slice in `cmd/scan.go`. If your
findings carry context that changes the real risk, extend `finding.Context` and
teach `RealRisk()` about it — that's where andas's identity lives.
