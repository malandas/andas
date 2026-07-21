package sast

import "regexp"

// A light, intra-procedural taint tracker. It follows one hop: a variable
// assigned from a user-input source becomes tainted, and any later line that
// references it (until the next function boundary) counts as user-reachable.
// This is deliberately conservative — it only ever RAISES a finding's
// confidence (never demotes), so a missed flow costs nothing and an
// over-eager one at worst adds a "likely exploitable" note to a real finding.

// reAssign captures `lhs = rhs` / `lhs := rhs`, excluding == comparisons.
var reAssign = regexp.MustCompile(`(\$?[A-Za-z_][\w]*)\s*:?=\s*([^=].*)$`)

// fnBoundary resets the tainted set at the start of a new function, keeping the
// analysis roughly intra-procedural without a full parser.
var fnBoundary = map[string]*regexp.Regexp{
	".py":  regexp.MustCompile(`^\s*def\s`),
	".rb":  regexp.MustCompile(`^\s*def\s`),
	".go":  regexp.MustCompile(`^\s*func\s`),
	".rs":  regexp.MustCompile(`\bfn\s`),
	".php": regexp.MustCompile(`\bfunction\s`),
	".js":  regexp.MustCompile(`\bfunction\b|=>`),
	".jsx": regexp.MustCompile(`\bfunction\b|=>`),
	".ts":  regexp.MustCompile(`\bfunction\b|=>`),
	".tsx": regexp.MustCompile(`\bfunction\b|=>`),
	".mjs": regexp.MustCompile(`\bfunction\b|=>`),
	".cjs": regexp.MustCompile(`\bfunction\b|=>`),
}

// reCallTaint matches a call whose arguments contain a user-input source, e.g.
// `handle(req.query.x)` — group 1 is the callee.
var reCallTaint = regexp.MustCompile(`([A-Za-z_]\w*)\s*\([^)]*(?:req\.(?:query|params|body)|request\.(?:args|form|json|data|GET|POST)|\$_(?:GET|POST|REQUEST)|params\[)`)

// fnDef extracts a function's name and first meaningful parameter, per language.
var fnDef = map[string]*regexp.Regexp{
	".py":  regexp.MustCompile(`^\s*def\s+(\w+)\s*\(\s*(?:self\s*,\s*)?(\w+)`),
	".rb":  regexp.MustCompile(`^\s*def\s+(\w+)\s*\(?\s*(\w+)`),
	".go":  regexp.MustCompile(`^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(\s*(\w+)`),
	".php": regexp.MustCompile(`\bfunction\s+(\w+)\s*\(\s*\$(\w+)`),
	".js":  regexp.MustCompile(`function\s+(\w+)\s*\(\s*([\w$]+)`),
	".ts":  regexp.MustCompile(`function\s+(\w+)\s*\(\s*([\w$]+)`),
	".jsx": regexp.MustCompile(`function\s+(\w+)\s*\(\s*([\w$]+)`),
	".tsx": regexp.MustCompile(`function\s+(\w+)\s*\(\s*([\w$]+)`),
}

// taintedLines returns, per line index, whether user-controlled input reaches it.
// It follows one inter-procedural hop: a function called with a user-input
// argument has its parameter treated as tainted inside its own body.
func taintedLines(lines []string, ext string) []bool {
	res := make([]bool, len(lines))
	tainted := map[string]bool{}
	reset := fnBoundary[ext]

	// Which locally-defined functions are ever called with tainted input?
	taintedCallees := map[string]bool{}
	for _, line := range lines {
		if m := reCallTaint.FindStringSubmatch(line); m != nil {
			taintedCallees[m[1]] = true
		}
	}
	def := fnDef[ext]

	for i, line := range lines {
		if reset != nil && reset.MatchString(line) {
			tainted = map[string]bool{}
			// Entering a function that's called with user input? Seed its
			// parameter as tainted for the length of its body.
			if def != nil {
				if m := def.FindStringSubmatch(line); m != nil && taintedCallees[m[1]] {
					tainted[m[2]] = true
				}
			}
		}
		direct := taintRe.MatchString(line)

		// An assignment whose right-hand side is (or came from) user input taints
		// the left-hand variable.
		if m := reAssign.FindStringSubmatch(line); m != nil {
			rhs := m[2]
			if taintRe.MatchString(rhs) || referencesTainted(rhs, tainted) {
				tainted[m[1]] = true
			}
		}

		res[i] = direct || referencesTainted(line, tainted)
	}
	return res
}

// referencesTainted reports whether s uses any currently-tainted variable as a
// whole token (handling the leading $ of PHP variables).
func referencesTainted(s string, tainted map[string]bool) bool {
	for v := range tainted {
		if wholeToken(s, v) {
			return true
		}
	}
	return false
}

func wholeToken(s, v string) bool {
	for start := 0; ; {
		i := indexFrom(s, v, start)
		if i < 0 {
			return false
		}
		beforeOK := i == 0 || !isIdentByte(s[i-1])
		end := i + len(v)
		afterOK := end >= len(s) || !isIdentByte(s[end])
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
	}
}

func indexFrom(s, sub string, from int) int {
	if from >= len(s) {
		return -1
	}
	if j := indexOf(s[from:], sub); j >= 0 {
		return from + j
	}
	return -1
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// isIdentByte reports whether b can be part of an identifier ($ included so a
// PHP "$foo" isn't matched inside "$foobar").
func isIdentByte(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
