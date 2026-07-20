package report

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/malandas/andas/internal/finding"
)

// A baseline records the fingerprints of findings a team has chosen to accept
// for now, so andas can scan a repo with existing debt and still fail CI only
// on *new* risk. The redacted matches are stored for human readability; the
// fingerprints are what's matched.
type baselineFile struct {
	Generated string           `json:"generated"`
	Entries   []baselineEntry  `json:"entries"`
	index     map[string]bool  // fingerprint set, built on load
}

type baselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	File        string `json:"file"`
	Note        string `json:"note,omitempty"`
}

// LoadBaseline reads a baseline file. A missing file is not an error — it just
// means nothing is suppressed yet.
func LoadBaseline(path string) (*baselineFile, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &baselineFile{index: map[string]bool{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var b baselineFile
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	b.index = make(map[string]bool, len(b.Entries))
	for _, e := range b.Entries {
		b.index[e.Fingerprint] = true
	}
	return &b, nil
}

// Filter splits findings into those NOT in the baseline (returned) and the count
// that was suppressed.
func (b *baselineFile) Filter(findings []finding.Finding) (kept []finding.Finding, suppressed int) {
	for _, f := range findings {
		if b.index[f.Fingerprint()] {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

// WriteBaseline records every current finding as accepted, so future scans
// report only what appears after this point. now is passed in (not read from
// the clock here) to keep the caller in control of the timestamp.
func WriteBaseline(path string, findings []finding.Finding, now time.Time) error {
	entries := make([]baselineEntry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, baselineEntry{
			Fingerprint: f.Fingerprint(),
			Rule:        f.RuleID,
			File:        f.File,
			Note:        f.Match,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Fingerprint < entries[j].Fingerprint })

	doc := baselineFile{Generated: now.UTC().Format(time.RFC3339), Entries: entries}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}
