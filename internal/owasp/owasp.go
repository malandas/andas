// Package owasp maps a CWE id to its OWASP Top 10 (2021) category. Pentest and
// AppSec reports are almost always organised by the Top 10, so andas annotates
// every code/config finding with the category a client's report will expect.
package owasp

// Category returns the OWASP Top 10 (2021) label for a CWE, or "" if unmapped.
func Category(cwe string) string {
	switch cwe {
	// A01: Broken Access Control
	case "CWE-22", "CWE-352", "CWE-601", "CWE-732", "CWE-434", "CWE-639":
		return "A01:2021 Broken Access Control"
	// A02: Cryptographic Failures
	case "CWE-321", "CWE-326", "CWE-327", "CWE-328", "CWE-338", "CWE-295", "CWE-614":
		return "A02:2021 Cryptographic Failures"
	// A03: Injection
	case "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-643", "CWE-917", "CWE-1336", "CWE-943", "CWE-95", "CWE-1333":
		return "A03:2021 Injection"
	// A05: Security Misconfiguration
	case "CWE-611", "CWE-16":
		return "A05:2021 Security Misconfiguration"
	// A07: Identification and Authentication Failures
	case "CWE-347", "CWE-287", "CWE-384":
		return "A07:2021 Identification & Authentication Failures"
	// A08: Software and Data Integrity Failures
	case "CWE-502", "CWE-1321", "CWE-915":
		return "A08:2021 Software & Data Integrity Failures"
	// A10: Server-Side Request Forgery
	case "CWE-918":
		return "A10:2021 Server-Side Request Forgery"
	default:
		return ""
	}
}

// Short returns just the "A0X" prefix, for compact grouping.
func Short(cwe string) string {
	c := Category(cwe)
	if len(c) >= 3 {
		return c[:3]
	}
	return ""
}
