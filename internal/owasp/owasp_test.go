package owasp

import "testing"

func TestCategory(t *testing.T) {
	cases := map[string]string{
		"CWE-78":   "A03:2021 Injection",
		"CWE-89":   "A03:2021 Injection",
		"CWE-22":   "A01:2021 Broken Access Control",
		"CWE-434":  "A01:2021 Broken Access Control",
		"CWE-328":  "A02:2021 Cryptographic Failures",
		"CWE-347":  "A07:2021 Identification & Authentication Failures",
		"CWE-502":  "A08:2021 Software & Data Integrity Failures",
		"CWE-918":  "A10:2021 Server-Side Request Forgery",
		"CWE-9999": "",
	}
	for cwe, want := range cases {
		if got := Category(cwe); got != want {
			t.Errorf("Category(%q) = %q, want %q", cwe, got, want)
		}
	}
	if Short("CWE-78") != "A03" {
		t.Errorf("Short(CWE-78) = %q, want A03", Short("CWE-78"))
	}
}
