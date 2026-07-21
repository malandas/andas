package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/malandas/andas/internal/scanner/surface"
)

// writeOpenAPI emits an OpenAPI 3.0 spec of the discovered endpoints and the
// request parameters the app reads. Both Burp Suite (OpenAPI Parser / import)
// and OWASP ZAP (native OpenAPI import) ingest it to build the site tree and
// seed active scans — so andas hands the tester a ready attack surface without
// ever touching a target itself.
func writeOpenAPI(w io.Writer, routes []surface.Route, params []string) error {
	type param struct {
		Name     string `json:"name"`
		In       string `json:"in"`
		Required bool   `json:"required"`
		Schema   any    `json:"schema"`
	}
	strSchema := map[string]string{"type": "string"}

	// Group methods by their OpenAPI-normalised path.
	pathOps := map[string]map[string][]param{}
	for _, r := range routes {
		p := toOpenAPIPath(r.Path)
		if pathOps[p] == nil {
			pathOps[p] = map[string][]param{}
		}
		method := strings.ToLower(r.Method)
		if method == "any" || method == "query" || method == "mutation" {
			method = "get" // GraphQL/wildcard → GET so it lands in the tree
		}
		// Path parameters, from the {id} placeholders in the template.
		var ps []param
		for _, pp := range pathParams(p) {
			ps = append(ps, param{Name: pp, In: "path", Required: true, Schema: strSchema})
		}
		// Discovered request params attached as query params — fields to fuzz.
		for _, qp := range params {
			ps = append(ps, param{Name: qp, In: "query", Required: false, Schema: strSchema})
		}
		pathOps[p][method] = ps
	}

	paths := map[string]any{}
	for p, ops := range pathOps {
		methods := map[string]any{}
		for m, ps := range ops {
			op := map[string]any{
				"summary":   "discovered by andas",
				"responses": map[string]any{"200": map[string]any{"description": "ok"}},
			}
			if len(ps) > 0 {
				op["parameters"] = ps
			}
			methods[m] = op
		}
		paths[p] = methods
	}

	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "andas — discovered attack surface",
			"version":     "1.0.0",
			"description": "Endpoints and parameters extracted from source by andas, for AUTHORISED assessment. Import into Burp Suite or OWASP ZAP.",
		},
		"servers": []any{map[string]any{"url": "https://TARGET"}},
		"paths":   paths,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// writeRequests writes one raw HTTP/1.1 request file per endpoint into dir —
// ready to paste straight into Burp Repeater (or `nc`/curl). Path params get a
// concrete "1", body-taking methods carry a JSON body of the discovered params,
// and GET/HEAD carry them as a query string. Host is the TARGET placeholder the
// tester replaces. andas only writes the files; it never sends them.
func writeRequests(dir string, routes []surface.Route, params []string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	used := map[string]bool{}
	n := 0
	for _, r := range routes {
		method := strings.ToUpper(r.Method)
		switch method {
		case "ANY":
			method = "GET"
		case "QUERY", "MUTATION":
			method = "POST" // GraphQL travels as POST /graphql
		}
		path := pathNoParams(toOpenAPIPath(r.Path))

		var reqLine, body, ctype string
		switch method {
		case "GET", "HEAD", "OPTIONS", "DELETE":
			q := ""
			if len(params) > 0 {
				var kv []string
				for _, p := range params {
					kv = append(kv, p+"=")
				}
				q = "?" + strings.Join(kv, "&")
			}
			reqLine = method + " " + path + q + " HTTP/1.1"
		default: // POST, PUT, PATCH
			ctype = "application/json"
			body = jsonBody(params)
			reqLine = method + " " + path + " HTTP/1.1"
		}

		var b strings.Builder
		b.WriteString(reqLine + "\r\n")
		b.WriteString("Host: TARGET\r\n")
		if ctype != "" {
			b.WriteString("Content-Type: " + ctype + "\r\n")
			b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		b.WriteString("Connection: close\r\n")
		b.WriteString("\r\n")
		b.WriteString(body)

		name := uniqueName(used, strings.ToLower(method)+"_"+slug(path))
		if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(b.String()), 0o644); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// jsonBody builds a JSON object with an empty string for each discovered param,
// so the tester has every field present and ready to fuzz.
func jsonBody(params []string) string {
	if len(params) == 0 {
		return "{}"
	}
	m := map[string]string{}
	for _, p := range params {
		m[p] = ""
	}
	out, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(out)
}

func uniqueName(used map[string]bool, base string) string {
	if base == "" {
		base = "root"
	}
	name := base
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	used[name] = true
	return name
}

var reRouteParam = regexp.MustCompile(`[:{](\w+)}?`)

// toOpenAPIPath converts framework path params to OpenAPI form: :id → {id}.
func toOpenAPIPath(p string) string {
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	// Drop a GraphQL "#field" fragment; keep just the base path.
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if strings.HasPrefix(seg, ":") {
			parts[i] = "{" + seg[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}

func pathParams(openapiPath string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reRouteParam.FindAllStringSubmatch(openapiPath, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}
