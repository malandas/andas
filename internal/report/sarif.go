package report

import (
	"encoding/json"
	"io"

	"github.com/malandas/andas/internal/finding"
)

// SARIF writes findings in SARIF 2.1.0 — the format GitHub code scanning, VS
// Code, and most security dashboards ingest. The level is driven by RealRisk,
// so a dead secret or unreachable CVE lands as a note, not an error, keeping
// the security tab focused on what actually matters.
func SARIF(w io.Writer, findings []finding.Finding) error {
	type msg struct {
		Text string `json:"text"`
	}
	type region struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type artifactLocation struct {
		URI string `json:"uri"`
	}
	type physicalLocation struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
		Region           *region          `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations"`
	}
	type driver struct {
		Name           string        `json:"name"`
		InformationURI string        `json:"informationUri"`
		Version        string        `json:"version"`
		Rules          []interface{} `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool     `json:"tool"`
		Results []result `json:"results"`
	}
	type sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	results := make([]result, 0, len(findings))
	for _, f := range findings {
		text := f.Title
		if f.Context.Note != "" {
			text += " — " + f.Context.Note
		}
		if f.Fix != "" {
			text += " Fix: " + f.Fix
		}
		var reg *region
		if f.Line > 0 {
			reg = &region{StartLine: f.Line}
		}
		results = append(results, result{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.RealRisk()),
			Message: msg{Text: text},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: f.File},
					Region:           reg,
				},
			}},
		})
	}

	doc := sarif{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "andas",
				InformationURI: "https://github.com/malandas/andas",
				Version:        "1.13.0",
				Rules:          []interface{}{},
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifLevel maps our real risk onto SARIF's three levels.
func sarifLevel(s finding.Severity) string {
	switch {
	case s >= finding.SevHigh:
		return "error"
	case s == finding.SevMedium:
		return "warning"
	default:
		return "note"
	}
}
