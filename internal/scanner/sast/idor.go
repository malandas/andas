package sast

import "regexp"

// IDOR (Insecure Direct Object Reference, CWE-639) is one of the highest-impact
// yet least-detected API flaws: an endpoint fetches an object by a user-supplied
// id without checking the caller owns it. We flag a lookup-by-request-id when no
// ownership/authorization check appears nearby — a heuristic, but a sharp one.

var reIDORLookup = regexp.MustCompile(`(?i)` +
	`(?:findById|findByPk|getById)\s*\(\s*req(?:uest)?\.(?:params|query|args)` + // ORM by-id from request
	`|\.findOne\s*\(\s*\{\s*_?id\s*:\s*req\.` + // Mongoose {id: req...}
	`|objects\.get\s*\(\s*(?:pk|id)\s*=\s*request` + // Django objects.get(pk=request...)
	`|get_object_or_404\s*\([^)]*request` + // Django shortcut
	`|\.find\s*\(\s*params\[:id\]` + // Rails Model.find(params[:id])
	`|WHERE\s+id\s*=\s*['"` + "`" + `]?\$?\{?(?:req|request|params)`) // raw SQL by request id

// reOwnership matches a check that ties the object to the current principal.
var reOwnership = regexp.MustCompile(`(?i)current_user|req\.user|request\.user|session\[|\bowner|user_id|account_id|@current|\bauthorize\b|\bcan\?|pundit|policy_scope|where\([^)]*user|filter\([^)]*user=`)

// detectIDOR reports whether line i is a by-id lookup with no ownership check in
// the surrounding window.
func detectIDOR(lines []string, i int) bool {
	if !reIDORLookup.MatchString(lines[i]) {
		return false
	}
	lo, hi := i-8, i+8
	if lo < 0 {
		lo = 0
	}
	if hi >= len(lines) {
		hi = len(lines) - 1
	}
	for j := lo; j <= hi; j++ {
		if reOwnership.MatchString(lines[j]) {
			return false // an ownership/authorization check is present — not IDOR
		}
	}
	return true
}
