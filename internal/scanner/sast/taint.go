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
	// C#: reset taint at each method/accessor declaration (an access modifier or
	// an HTTP-verb attribute marks a new action body).
	".cs": regexp.MustCompile(`^\s*(?:\[Http|(?:public|private|protected|internal|static|async|override|virtual)\s)`),
}

// reCallTaint matches a call whose arguments contain a user-input source, e.g.
// `handle(req.query.x)` — group 1 is the callee.
var reCallTaint = regexp.MustCompile(`([A-Za-z_]\w*)\s*\([^)]*(?:req\.(?:query|params|body)|request\.(?:args|form|json|data|GET|POST)|\$_(?:GET|POST|REQUEST)|params\[)`)

// C# action-method detection: in ASP.NET Core every parameter of an action
// (a method carrying an [HttpVerb] attribute) is model-bound from the request,
// so it is user-controlled. These recognise the attribute, a method signature,
// and strip parameter attributes so the bound name can be seeded as tainted.
var (
	reCsHttpAttr   = regexp.MustCompile(`\[Http(?:Get|Post|Put|Delete|Patch|Head|Options)\b`)
	reCsMethodDecl = regexp.MustCompile(`^\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal)\b[^;={]*\([^;]*\)`)
	reCsParamAttr  = regexp.MustCompile(`\[[^\]]*\]`)
)

// csParams extracts the bound parameter names from a single-line C# method
// signature, e.g. `public IActionResult Run([FromForm] string cmd, int id=0)`
// -> ["cmd", "id"].
func csParams(line string) []string {
	l := indexOf(line, "(")
	if l < 0 {
		return nil
	}
	// Take the parameter list only: from the first '(' to its MATCHING ')', so a
	// sink call later on the same line (expression-bodied methods) isn't consumed.
	depth, r := 0, -1
	for i := l; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				r = i
			}
		}
		if r >= 0 {
			break
		}
	}
	if r <= l {
		return nil
	}
	inner := line[l+1 : r]
	if len(inner) == 0 {
		return nil
	}
	var out []string
	for _, part := range splitTop(inner, ',') {
		part = reCsParamAttr.ReplaceAllString(part, " ")
		if eq := indexOf(part, "="); eq >= 0 { // drop default value
			part = part[:eq]
		}
		fields := fieldsOf(part)
		if len(fields) < 2 { // need at least a type and a name
			continue
		}
		name := fields[len(fields)-1]
		if len(name) > 0 && name[0] == '@' {
			name = name[1:]
		}
		if isIdentToken(name) {
			out = append(out, name)
		}
	}
	return out
}

// splitTop splits on sep at the top nesting level only, so generics like
// Dictionary<int,string> in a parameter type don't split a parameter in two.
func splitTop(s string, sep byte) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<', '(', '[':
			depth++
		case '>', ')', ']':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func fieldsOf(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func isIdentToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}

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

	// ASP.NET Core: the parameters of an action method (one carrying an
	// [HttpVerb] attribute) are all model-bound from the request. Precompute,
	// per line, the parameter names to seed as tainted when entering that body.
	csActionSeed := map[int][]string{}
	if ext == ".cs" {
		lastHTTP := -100
		for i, line := range lines {
			if reCsHttpAttr.MatchString(line) {
				lastHTTP = i
			}
			if reCsMethodDecl.MatchString(line) && i-lastHTTP <= 4 {
				if ps := csParams(line); len(ps) > 0 {
					csActionSeed[i] = ps
				}
			}
		}
	}

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
		// ASP.NET action parameters are user-controlled — seed them all.
		for _, p := range csActionSeed[i] {
			tainted[p] = true
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
