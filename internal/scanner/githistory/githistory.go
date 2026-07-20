package githistory

import (
	"fmt"
	"os"

	"github.com/malandas/andas/internal/finding"
	"github.com/malandas/andas/internal/scanner"
	"github.com/malandas/andas/internal/scanner/secrets"
)

const maxBlobBytes = 2 << 20 // 2 MiB

// Scanner sweeps the full git history for secrets that no longer appear in the
// working tree — the ones an ordinary file scan can never see.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "git-history" }

func (s *Scanner) Scan(root string, opts scanner.Options) ([]finding.Finding, error) {
	if !isRepo(root) {
		fmt.Fprintln(os.Stderr, "andas: --history set but this is not a git repository; skipping history scan")
		return nil, nil
	}

	shas, err := allBlobShas(root, maxBlobBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: could not enumerate git objects (%v); skipping history scan\n", err)
		return nil, nil
	}
	blobs, err := readBlobs(root, shas)
	if err != nil {
		fmt.Fprintf(os.Stderr, "andas: could not read git objects (%v); skipping history scan\n", err)
		return nil, nil
	}
	fmt.Fprintf(os.Stderr, "andas: scanned %d blobs across git history\n", len(blobs))

	// Dedupe by secret value: the same leak recurs across many commits, but it's
	// one credential to rotate. Keep one representative blob for attribution and
	// for AWS pairing context.
	type agg struct {
		match   secrets.RawMatch
		blobSHA string
		context string
	}
	uniq := map[string]*agg{}
	for _, b := range blobs {
		for _, m := range secrets.Detect(b.Content, opts.Entropy) {
			if _, seen := uniq[m.Secret]; !seen {
				uniq[m.Secret] = &agg{match: m, blobSHA: b.SHA, context: string(b.Content)}
			}
		}
	}

	var out []finding.Finding
	for secret, a := range uniq {
		// The regular file scanner already covers secrets still in the tree.
		// history's unique value is the ones that were *removed* but persist.
		if inWorkingTree(root, secret) {
			continue
		}

		fnd := finding.Finding{
			Kind:     finding.KindSecret,
			RuleID:   a.match.RuleID,
			Title:    a.match.Title + " (in git history)",
			Match:    finding.Redact(secret),
			Severity: a.match.Severity,
			Fix:      secrets.Fix(a.match.RuleID),
		}

		commit, author, date := commitInfo(root, a.blobSHA)
		if commit != "" {
			fnd.File = fmt.Sprintf("git history @ %s (%s, %s)", commit, author, date)
		} else {
			fnd.File = "git history"
		}

		base := "removed from HEAD but still recoverable from history"
		if opts.Validate {
			validated, res := secrets.ValidateMatch(a.match, a.context, opts.TimeoutS)
			if validated {
				res.Note = base + " — " + res.Note
				secrets.ApplyResult(&fnd.Context, res)
			} else {
				fnd.Context.Note = base + " — " + res.Note
			}
		} else {
			fnd.Context.Note = base
		}
		out = append(out, fnd)
	}
	return out, nil
}
