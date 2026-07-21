# Contributing to andas

Thanks for your interest — andas is a friendly project and contributions of every
size are welcome, from a typo fix to a whole new scanner.

## Ground rules

andas has two non-negotiable principles. Please keep them in mind:

1. **Read-only.** andas observes and reports. It never edits code, rotates keys,
   opens PRs, or mutates anything the user didn't explicitly ask it to write
   (reports, baselines, the git hook). No auto-remediation.
2. **Real risk over noise.** Every finding should be actionable. Prefer a
   tight, high-signal rule that occasionally misses over a broad one that floods
   the user. When in doubt, add context (is it live? reachable? user-controlled?)
   rather than raising the alarm louder.

Also: **no third-party dependencies.** The whole tool builds from the Go standard
library, so it ships as one small binary. A PR that adds a module to `go.mod`
needs a very good reason.

## Getting started

```sh
git clone https://github.com/malandas/andas
cd andas
go build -o andas .
go test ./...
go vet ./...
```

andas even scans itself in CI (`andas scan . --offline --fail-on high`), so keep
that green — if you add a test fixture with a deliberately vulnerable pattern,
put it in a `_test.go` file (they're excluded via `.andasignore`).

## Good first contributions

- **A new secret validator.** Add a rule in `internal/scanner/secrets/rules.go`
  and a `validate*` function in `validate.go` (a single read-only request to the
  provider's own API). See `validateGitHub` for the shape.
- **A new SAST rule.** Add a tight, CWE-tagged pattern to
  `internal/scanner/sast/rules.go`. Include a test in `sast_test.go` proving it
  fires on vulnerable code *and* stays quiet on the safe idiom.
- **A new IaC rule** in `internal/scanner/iac/iac.go`.
- **Reachability for another ecosystem** in `internal/scanner/deps/`.

Browse [ARCHITECTURE.md](ARCHITECTURE.md) for the lay of the land.

## Pull requests

- One focused change per PR.
- `go test ./...` and `go vet ./...` must pass; add tests for new behaviour.
- Match the surrounding code style; keep comments explaining *why*, not *what*.
- Describe what a reviewer should look at and how you verified it.

By contributing you agree your work is licensed under the project's [MIT
license](LICENSE).
