package deps

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/malandas/andas/internal/finding"
)

// OSV.dev is Google's open vulnerability database — free, no API key. We use
// its batch endpoint to find which packages are affected in a single request,
// then fetch details only for the (usually few) that are.
const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"
)

// advisory is a single vulnerability affecting a package.
type advisory struct {
	ID       string
	Summary  string
	Severity finding.Severity
}

// queryOSV returns advisories keyed by package name for every package in g.
func queryOSV(g *graph, timeoutS int) (map[string][]advisory, error) {
	if timeoutS <= 0 {
		timeoutS = 15
	}
	client := &http.Client{Timeout: time.Duration(timeoutS) * time.Second}

	// Stable ordering so batch results line up with the packages we sent.
	names := make([]string, 0, len(g.byName))
	for name := range g.byName {
		names = append(names, name)
	}

	type osvQuery struct {
		Version string `json:"version"`
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	}
	var batch struct {
		Queries []osvQuery `json:"queries"`
	}
	for _, name := range names {
		var q osvQuery
		q.Version = g.byName[name].Version
		q.Package.Name = name
		q.Package.Ecosystem = "npm"
		batch.Queries = append(batch.Queries, q)
	}

	body, _ := json.Marshal(batch)
	resp, err := client.Post(osvBatchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var batchResp struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, err
	}

	out := map[string][]advisory{}
	for i, res := range batchResp.Results {
		if i >= len(names) || len(res.Vulns) == 0 {
			continue
		}
		name := names[i]
		for _, v := range res.Vulns {
			out[name] = append(out[name], fetchDetails(client, v.ID))
		}
	}
	return out, nil
}

// fetchDetails resolves a vuln ID to its summary and severity. On any failure
// it degrades to a bare advisory at MEDIUM rather than dropping the finding.
func fetchDetails(client *http.Client, id string) advisory {
	adv := advisory{ID: id, Summary: id, Severity: finding.SevMedium}
	resp, err := client.Get(osvVulnURL + id)
	if err != nil {
		return adv
	}
	defer resp.Body.Close()

	var d struct {
		Summary          string `json:"summary"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if json.NewDecoder(resp.Body).Decode(&d) != nil {
		return adv
	}
	if d.Summary != "" {
		adv.Summary = d.Summary
	}
	if s := mapSeverity(d.DatabaseSpecific.Severity); s >= 0 {
		adv.Severity = s
	}
	return adv
}

// mapSeverity converts a GitHub-advisory severity word to our scale; -1 if
// unknown so the caller keeps its default.
func mapSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return finding.SevCritical
	case "HIGH":
		return finding.SevHigh
	case "MODERATE", "MEDIUM":
		return finding.SevMedium
	case "LOW":
		return finding.SevLow
	default:
		return -1
	}
}
