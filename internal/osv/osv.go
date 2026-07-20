// Package osv is a small client for OSV.dev, shared by the dependency scanner
// and the container-image scanner. It batches the "which packages are affected"
// query into one request, then fetches details for the affected few
// concurrently — the network is the bottleneck, so parallelism matters most here.
package osv

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/malandas/andas/internal/finding"
)

const (
	batchURL = "https://api.osv.dev/v1/querybatch"
	vulnURL  = "https://api.osv.dev/v1/vulns/"
)

// Ref is a package resolved to a name, version, and OSV ecosystem.
type Ref struct {
	Name      string
	Version   string
	Ecosystem string
}

// Advisory is one vulnerability affecting a package.
type Advisory struct {
	ID       string
	Summary  string
	Severity finding.Severity
}

// maxDetailWorkers bounds concurrent detail fetches so we stay polite to OSV.
const maxDetailWorkers = 12

// Query returns advisories keyed by package name for every ref. Refs may span
// ecosystems — OSV's batch endpoint carries the ecosystem per query.
func Query(refs []Ref, timeoutS int) (map[string][]Advisory, error) {
	if len(refs) == 0 {
		return map[string][]Advisory{}, nil
	}
	if timeoutS <= 0 {
		timeoutS = 15
	}
	client := &http.Client{Timeout: time.Duration(timeoutS) * time.Second}

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
	for _, r := range refs {
		var q osvQuery
		q.Version = r.Version
		q.Package.Name = r.Name
		q.Package.Ecosystem = r.Ecosystem
		batch.Queries = append(batch.Queries, q)
	}

	body, _ := json.Marshal(batch)
	resp, err := client.Post(batchURL, "application/json", bytes.NewReader(body))
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

	// Collect the unique vuln IDs to resolve, and which package each belongs to.
	type hit struct{ name, id string }
	var hits []hit
	for i, res := range batchResp.Results {
		if i >= len(refs) {
			break
		}
		for _, v := range res.Vulns {
			hits = append(hits, hit{refs[i].Name, v.ID})
		}
	}

	// Fetch details concurrently (bounded).
	details := make([]Advisory, len(hits))
	sem := make(chan struct{}, maxDetailWorkers)
	var wg sync.WaitGroup
	for i, h := range hits {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, id string) {
			defer wg.Done()
			defer func() { <-sem }()
			details[i] = fetchDetails(client, id)
		}(i, h.id)
	}
	wg.Wait()

	out := map[string][]Advisory{}
	for i, h := range hits {
		out[h.name] = append(out[h.name], details[i])
	}
	return out, nil
}

// fetchDetails resolves a vuln ID to its summary and severity; on any failure it
// degrades to a bare advisory at MEDIUM rather than dropping the finding.
func fetchDetails(client *http.Client, id string) Advisory {
	adv := Advisory{ID: id, Summary: id, Severity: finding.SevMedium}
	resp, err := client.Get(vulnURL + id)
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
