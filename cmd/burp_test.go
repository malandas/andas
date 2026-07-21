package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/malandas/andas/internal/scanner/surface"
)

func TestWriteOpenAPI(t *testing.T) {
	routes := []surface.Route{
		{Method: "GET", Path: "/api/users/:id", Framework: "express"},
		{Method: "POST", Path: "/api/login", Framework: "express"},
		{Method: "QUERY", Path: "/graphql#me", Framework: "graphql"},
	}
	params := []string{"filter", "username"}

	var buf bytes.Buffer
	if err := writeOpenAPI(&buf, routes, params); err != nil {
		t.Fatalf("writeOpenAPI: %v", err)
	}

	var doc struct {
		OpenAPI string `json:"openapi"`
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc.OpenAPI != "3.0.3" {
		t.Errorf("openapi version = %q, want 3.0.3", doc.OpenAPI)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].URL != "https://TARGET" {
		t.Errorf("servers = %+v, want one https://TARGET", doc.Servers)
	}

	// :id must be normalised to an OpenAPI path parameter.
	users, ok := doc.Paths["/api/users/{id}"]
	if !ok {
		t.Fatalf("missing normalised path /api/users/{id}; paths = %v", keys(doc.Paths))
	}
	get, ok := users["get"]
	if !ok {
		t.Fatalf("GET op missing on /api/users/{id}")
	}
	var hasPathID, hasQueryFilter bool
	for _, p := range get.Parameters {
		if p.Name == "id" && p.In == "path" {
			hasPathID = true
		}
		if p.Name == "filter" && p.In == "query" {
			hasQueryFilter = true
		}
	}
	if !hasPathID {
		t.Error("path param {id} not emitted as an in:path parameter")
	}
	if !hasQueryFilter {
		t.Error("discovered param 'filter' not attached as an in:query parameter")
	}

	// GraphQL QUERY must fold into GET with the fragment stripped.
	if _, ok := doc.Paths["/graphql"]; !ok {
		t.Errorf("graphql path not normalised; paths = %v", keys(doc.Paths))
	} else if _, ok := doc.Paths["/graphql"]["get"]; !ok {
		t.Error("graphql QUERY was not folded into a GET operation")
	}
}

func TestWriteRequests(t *testing.T) {
	dir := t.TempDir()
	routes := []surface.Route{
		{Method: "POST", Path: "/api/login"},
		{Method: "GET", Path: "/api/users/:id"},
	}
	params := []string{"username", "password"}

	n, err := writeRequests(dir, routes, params)
	if err != nil {
		t.Fatalf("writeRequests: %v", err)
	}
	if n != 2 {
		t.Fatalf("wrote %d files, want 2", n)
	}

	post, err := os.ReadFile(filepath.Join(dir, "post_api-login.txt"))
	if err != nil {
		t.Fatalf("reading POST request file: %v", err)
	}
	ps := string(post)
	if !strings.HasPrefix(ps, "POST /api/login HTTP/1.1\r\n") {
		t.Errorf("POST request line/CRLF wrong:\n%q", ps)
	}
	if !strings.Contains(ps, "Host: TARGET\r\n") {
		t.Error("POST missing Host: TARGET")
	}
	// Body must be valid JSON carrying every param, with a matching Content-Length.
	body := ps[strings.Index(ps, "\r\n\r\n")+4:]
	var fields map[string]string
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatalf("POST body is not valid JSON: %v (%q)", err, body)
	}
	for _, p := range params {
		if _, ok := fields[p]; !ok {
			t.Errorf("POST body missing param %q", p)
		}
	}
	for _, line := range strings.Split(ps, "\r\n") {
		if v, ok := strings.CutPrefix(line, "Content-Length: "); ok {
			if n, _ := strconv.Atoi(v); n != len(body) {
				t.Errorf("Content-Length = %s, want %d (actual body len)", v, len(body))
			}
		}
	}

	// GET: path param becomes concrete "1"; params ride in the query string.
	get, err := os.ReadFile(filepath.Join(dir, "get_api-users-1.txt"))
	if err != nil {
		t.Fatalf("reading GET request file: %v", err)
	}
	gs := string(get)
	if !strings.HasPrefix(gs, "GET /api/users/1?") {
		t.Errorf("GET request line wrong (path param not concretised?):\n%q", gs)
	}
	if !strings.Contains(gs, "username=") || !strings.Contains(gs, "password=") {
		t.Errorf("GET query string missing params:\n%q", gs)
	}
}

func keys(m map[string]map[string]struct {
	Parameters []struct {
		Name string `json:"name"`
		In   string `json:"in"`
	} `json:"parameters"`
}) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
