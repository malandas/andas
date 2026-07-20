package secrets

import (
	"reflect"
	"testing"
)

func TestParseScopeHeader(t *testing.T) {
	got := parseScopeHeader("repo, gist, admin:org")
	want := []string{"repo", "gist", "admin:org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseScopeHeader = %v, want %v", got, want)
	}
	if p := parseScopeHeader(""); len(p) != 0 {
		t.Errorf("empty header should yield no scopes, got %v", p)
	}
}

func TestGithubPrivileged(t *testing.T) {
	privileged := [][]string{
		{"repo"},
		{"read:user", "delete_repo"},
		{"admin:org"},
		{"admin:enterprise"},
		{"gist", "workflow"},
	}
	for _, s := range privileged {
		if !githubPrivileged(s) {
			t.Errorf("githubPrivileged(%v) = false, want true", s)
		}
	}
	safe := [][]string{
		{"read:user"},
		{"gist"},
		{"read:org", "user:email"},
		{},
	}
	for _, s := range safe {
		if githubPrivileged(s) {
			t.Errorf("githubPrivileged(%v) = true, want false", s)
		}
	}
}

func TestJSONHelpers(t *testing.T) {
	body := []byte(`{"login":"alice","ok":true,"scopes":["mail.send","admin"]}`)
	if got := jsonString(body, "login"); got != "alice" {
		t.Errorf("jsonString login = %q, want alice", got)
	}
	if !jsonBool(body, "ok") {
		t.Error("jsonBool ok = false, want true")
	}
	if got := jsonStringSlice(body, "scopes"); !reflect.DeepEqual(got, []string{"mail.send", "admin"}) {
		t.Errorf("jsonStringSlice scopes = %v", got)
	}
	// Malformed input must not panic.
	if jsonString([]byte("not json"), "login") != "" {
		t.Error("jsonString on garbage should be empty")
	}
}

func TestAWSBlastRadius(t *testing.T) {
	xml := []byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
		`<Arn>arn:aws:iam::123456789012:user/deploy-bot</Arn>` +
		`<Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
	if arn := awsArn(xml); arn != "arn:aws:iam::123456789012:user/deploy-bot" {
		t.Errorf("awsArn = %q", arn)
	}
	if acct := awsAccount(xml); acct != "123456789012" {
		t.Errorf("awsAccount = %q", acct)
	}
	if awsPrivileged("arn:aws:iam::123456789012:user/deploy-bot") {
		t.Error("a plain user ARN should not be flagged privileged")
	}
	if !awsPrivileged("arn:aws:iam::123456789012:root") {
		t.Error("the account root must be flagged privileged")
	}
	if !awsPrivileged("arn:aws:iam::1:user/AdminAccess") {
		t.Error("an admin-named identity should be flagged privileged")
	}
}

func TestHasAdminScope(t *testing.T) {
	if !hasAdminScope([]string{"mail.send", "admin.reports"}) {
		t.Error("should detect an admin scope")
	}
	if hasAdminScope([]string{"mail.send", "read"}) {
		t.Error("should not flag non-admin scopes")
	}
}
