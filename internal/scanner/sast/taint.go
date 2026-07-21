package sast

import (
	"path/filepath"
	"regexp"

	"github.com/malandas/andas/internal/scanner"
)

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

// reCallName matches a call site `foo(` — group 1 is the callee. Used with
// balancedArgs so nested calls (`Ok(svc.Load(id))`) are all discovered, which a
// single `[^)]*` regex would miss.
var reCallName = regexp.MustCompile(`([A-Za-z_]\w*)\s*\(`)

// balancedArgs returns the argument text between the '(' at index open and its
// matching ')'.
func balancedArgs(s string, open int) string {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return s[open+1 : i]
			}
		}
	}
	return s[open+1:]
}

// callKeywords are control-flow constructs that look like calls but aren't, so
// they're never treated as tainted callees.
var callKeywords = map[string]bool{
	"if": true, "for": true, "foreach": true, "while": true, "switch": true,
	"catch": true, "return": true, "func": true, "function": true, "def": true,
	"using": true, "lock": true, "await": true, "yield": true, "sizeof": true,
}

// taintedLines returns, per line index, whether user-controlled input reaches it.
// Taint follows call chains to a fixpoint: a function called with a user-input
// argument — directly OR via a tainted variable — has its parameter treated as
// tainted, so a dangerous sink several calls deep is still marked reachable.
func taintedLines(lines []string, ext string) []bool {
	reset := fnBoundary[ext]
	def := fnDef[ext]

	// ASP.NET Core: an action method's parameters are all model-bound from the
	// request. Precompute the parameter names to seed as tainted per line.
	csActionSeed := csActionSeeds(lines, ext)

	// Fast path: if the file has no user-input source at all, nothing is ever
	// tainted — skip the whole analysis (most files hit this).
	hasSource := len(csActionSeed) > 0
	if !hasSource {
		for _, line := range lines {
			if taintRe.MatchString(line) {
				hasSource = true
				break
			}
		}
	}
	if !hasSource {
		return make([]bool, len(lines))
	}

	// Seed with functions called with a direct user-input source, then grow the
	// set transitively until it stops changing (bounded for safety).
	taintedCallees := map[string]bool{}
	for _, line := range lines {
		if m := reCallTaint.FindStringSubmatch(line); m != nil {
			taintedCallees[m[1]] = true
		}
	}
	for iter := 0; iter < 12; iter++ {
		pr := taintPass(lines, ext, reset, def, csActionSeed, taintedCallees, true)
		added := false
		for c := range pr.discovered {
			if !callKeywords[c] && !taintedCallees[c] {
				taintedCallees[c] = true
				added = true
			}
		}
		if !added {
			break
		}
	}

	return taintPass(lines, ext, reset, def, csActionSeed, taintedCallees, false).tainted
}

// crossFileTaint computes tainted lines for every file at once, following taint
// through calls that cross file boundaries — the shape of real .NET/Node apps,
// where a controller passes user input to a service or repository defined
// elsewhere. To stay precise, a call only propagates cross-file when its target
// method is defined EXACTLY ONCE in the codebase, so a common name like Save or
// Get can't taint every same-named method everywhere.
// fileTaint holds a file's per-line taint verdicts: whether user input reaches
// the line, and whether that input has been HTML-encoded (so an XSS finding
// there is not actually exploitable).
type fileTaint struct {
	tainted  []bool
	htmlSafe []bool
	origin   []int // 1-indexed source line for each reaching-input line
}

func crossFileTaint(files []scanner.TextFile) map[string]fileTaint {
	type tf struct {
		f          scanner.TextFile
		ext        string
		reset, def *regexp.Regexp
		seed       map[int][]string
		hasSource  bool
		defNames   []string
	}
	var tfs []tf
	global := map[string]bool{} // tainted method names (uniqueness-guarded)
	defCount := map[string]int{}

	for _, f := range files {
		ext := filepath.Ext(f.Path)
		t := tf{f: f, ext: ext, reset: fnBoundary[ext], def: fnDef[ext], seed: csActionSeeds(f.Lines, ext)}
		t.hasSource = len(t.seed) > 0
		names := map[string]bool{}
		for _, line := range f.Lines {
			if !t.hasSource && taintRe.MatchString(line) {
				t.hasSource = true
			}
			if m := reCallTaint.FindStringSubmatch(line); m != nil {
				global[m[1]] = true
			}
			if t.def != nil {
				if m := t.def.FindStringSubmatch(line); m != nil {
					names[m[1]] = true
				}
			}
			if ext == ".cs" {
				if m := reCsMethodName.FindStringSubmatch(line); m != nil {
					names[m[1]] = true
				}
			}
		}
		for n := range names {
			t.defNames = append(t.defNames, n)
			defCount[n]++
		}
		tfs = append(tfs, t)
	}

	// Keep only uniquely-defined targets in the tainted set.
	for name := range global {
		if defCount[name] != 1 {
			delete(global, name)
		}
	}
	addGlobal := func(name string) bool {
		if callKeywords[name] || global[name] || defCount[name] != 1 {
			return false
		}
		global[name] = true
		return true
	}
	participates := func(t tf) bool {
		if t.hasSource {
			return true
		}
		for _, n := range t.defNames {
			if global[n] {
				return true
			}
		}
		return false
	}

	for iter := 0; iter < 12; iter++ {
		added := false
		for _, t := range tfs {
			if !participates(t) {
				continue
			}
			pr := taintPass(t.f.Lines, t.ext, t.reset, t.def, t.seed, global, true)
			for c := range pr.discovered {
				if addGlobal(c) {
					added = true
				}
			}
		}
		if !added {
			break
		}
	}

	out := make(map[string]fileTaint, len(tfs))
	for _, t := range tfs {
		if !participates(t) {
			n := len(t.f.Lines)
			out[t.f.Path] = fileTaint{tainted: make([]bool, n), htmlSafe: make([]bool, n), origin: make([]int, n)}
			continue
		}
		pr := taintPass(t.f.Lines, t.ext, t.reset, t.def, t.seed, global, false)
		out[t.f.Path] = fileTaint{tainted: pr.tainted, htmlSafe: pr.htmlSafe, origin: pr.origin}
	}
	return out
}

// csActionSeeds precomputes, per line, the ASP.NET action-method parameters to
// seed as tainted (all params of a method carrying an [HttpVerb] attribute).
func csActionSeeds(lines []string, ext string) map[int][]string {
	seed := map[int][]string{}
	if ext != ".cs" {
		return seed
	}
	lastHTTP := -100
	for i, line := range lines {
		if reCsHttpAttr.MatchString(line) {
			lastHTTP = i
		}
		if reCsMethodDecl.MatchString(line) && i-lastHTTP <= 4 {
			if ps := csParams(line); len(ps) > 0 {
				seed[i] = ps
			}
		}
	}
	return seed
}

// taintPass runs one intra-procedural sweep with the given tainted-callee set.
// It returns, per line, whether user input reaches it, and the set of callees it
// saw invoked with tainted/source arguments (candidates for the next fixpoint
// round).
// reCsMethodName captures a C# method's name from its declaration, so a service
// method called with tainted input (in another file) can have its parameters
// seeded — the key to following taint from a controller into a service.
var reCsMethodName = regexp.MustCompile(`(?:public|private|protected|internal)\b[^;={(]*\s(\w+)\s*\(`)

// passResult is one taint sweep's per-line verdicts plus the callees it saw
// invoked with tainted input (for the next fixpoint round).
type passResult struct {
	tainted    []bool
	htmlSafe   []bool
	origin     []int // 1-indexed line where the reaching input entered (0 = unknown)
	discovered map[string]bool
}

func taintPass(lines []string, ext string, reset, def *regexp.Regexp, csActionSeed map[int][]string, taintedCallees map[string]bool, collect bool) passResult {
	res := make([]bool, len(lines))
	htmlSafe := make([]bool, len(lines))
	origin := make([]int, len(lines))
	discovered := map[string]bool{}
	tainted := map[string]bool{}
	hsafe := map[string]bool{}   // tainted vars that have been HTML/URL-encoded (XSS-safe)
	src := map[string]int{}      // tainted var -> 1-indexed line where its taint originated

	for i, line := range lines {
		if reset != nil && reset.MatchString(line) {
			tainted = map[string]bool{}
			hsafe = map[string]bool{}
			src = map[string]int{}
			if def != nil {
				if m := def.FindStringSubmatch(line); m != nil && taintedCallees[m[1]] {
					tainted[m[2]] = true
					src[m[2]] = i + 1
				}
			}
			// C# method whose name is called with tainted input: seed all its
			// parameters (model/DTO carrying user data into the service).
			if ext == ".cs" {
				if m := reCsMethodName.FindStringSubmatch(line); m != nil && taintedCallees[m[1]] {
					for _, p := range csParams(line) {
						tainted[p] = true
						src[p] = i + 1
					}
				}
			}
		}
		for _, p := range csActionSeed[i] {
			tainted[p] = true
			if src[p] == 0 {
				src[p] = i + 1
			}
		}
		direct := taintRe.MatchString(line)

		// Verdict for this line is computed from the taint state BEFORE applying
		// this line's own assignment, so a sink like `el.innerHTML = name` is
		// judged by what it READS (name), not the variable it writes.
		res[i] = direct || referencesTainted(line, tainted)
		if res[i] {
			// XSS-safe only if no direct source and every tainted var here is
			// HTML-encoded. Also record where the reaching input entered.
			allSafe, any := true, false
			earliest := 0
			if direct {
				earliest = i + 1 // the source is on this very line
			}
			for v := range tainted {
				if wholeToken(line, v) {
					any = true
					if !hsafe[v] {
						allSafe = false
					}
					if s := src[v]; s != 0 && (earliest == 0 || s < earliest) {
						earliest = s
					}
				}
			}
			if !direct {
				htmlSafe[i] = any && allSafe
			}
			origin[i] = earliest
		}

		if m := reAssign.FindStringSubmatch(line); m != nil {
			lhs, rhs := m[1], m[2]
			if taintRe.MatchString(rhs) || referencesTainted(rhs, tainted) {
				switch {
				case isSanitized(rhs):
					// Numeric/typed coercion neutralises injection entirely.
					delete(tainted, lhs)
					delete(hsafe, lhs)
					delete(src, lhs)
				case isXSSSanitized(rhs):
					// HTML/URL-encoded: safe for an XSS sink, still raw for others.
					tainted[lhs] = true
					hsafe[lhs] = true
					setOrigin(src, lhs, rhs, tainted, direct, i)
				default:
					tainted[lhs] = true
					delete(hsafe, lhs)
					setOrigin(src, lhs, rhs, tainted, direct, i)
				}
			}
		}

		// A callee invoked with a tainted/source argument propagates taint into
		// its body on the next round. Nested calls are included so taint passed
		// through a wrapper (Ok(svc.Load(id))) is still followed.
		if collect {
			for _, loc := range reCallName.FindAllStringSubmatchIndex(line, -1) {
				args := balancedArgs(line, loc[1]-1)
				if taintRe.MatchString(args) || referencesTainted(args, tainted) {
					discovered[line[loc[2]:loc[3]]] = true
				}
			}
		}
	}
	return passResult{tainted: res, htmlSafe: htmlSafe, origin: origin, discovered: discovered}
}

// setOrigin records where the taint assigned to lhs came from: this line if the
// right-hand side holds a direct source, else the earliest source among the
// tainted variables it references (so the flow points back to the real entry).
func setOrigin(src map[string]int, lhs, rhs string, tainted map[string]bool, directLine bool, i int) {
	if taintRe.MatchString(rhs) {
		src[lhs] = i + 1
		return
	}
	best := 0
	for v := range tainted {
		if v != lhs && wholeToken(rhs, v) {
			if s := src[v]; s != 0 && (best == 0 || s < best) {
				best = s
			}
		}
	}
	if best == 0 {
		best = i + 1
	}
	src[lhs] = best
}

// reXSSSanitizer matches an HTML/URL/attribute encoder — output that is safe for
// an XSS sink but NOT for SQL/command/path sinks, so it only ever clears the
// XSS-specific finding, never a different injection class.
var reXSSSanitizer = regexp.MustCompile(`^\s*(?:` +
	`encodeURIComponent|encodeURI|escapeHtml|DOMPurify\.sanitize|sanitizeHtml|he\.encode` + // JS
	`|html\.escape|markupsafe\.escape|bleach\.clean` + // Python
	`|HtmlEncoder\.Encode|HttpUtility\.HtmlEncode|WebUtility\.HtmlEncode|AntiXss\.\w*Encode|Uri\.EscapeDataString` + // C#
	`|StringEscapeUtils\.escapeHtml\w*|HtmlUtils\.htmlEscape|ESAPI\.encoder` + // Java
	`)\s*\(`)

func isXSSSanitized(rhs string) bool { return reXSSSanitizer.MatchString(rhs) }

// reSanitizer matches a right-hand side whose OUTERMOST operation is a
// numeric/typed coercion. Such a value can no longer carry an injection payload
// (it is an int/float/bool/guid/date), so taint stops here. Deliberately narrow:
// string coercions (String(), .toString()) are NOT sanitizers and are excluded.
var reSanitizer = regexp.MustCompile(`^\s*(?:` +
	`\(\s*(?:u?int|u?long|u?short|byte|float|double|decimal|bool|Guid|DateTime)\s*\)` + // C# cast (int)x
	`|parseInt|parseFloat|Number|Boolean` + // JS
	`|(?:u?int|u?long|u?short|byte|float|double|decimal|bool|Guid|DateTime)\.(?:Parse|TryParse)` + // C# int.Parse
	`|Convert\.To(?:Int\d*|Int|Double|Decimal|Boolean|Single|Byte)` + // C# Convert.ToInt32
	`|Integer\.parseInt|Long\.parseLong|Double\.parseDouble|Float\.parseFloat|Boolean\.parseBoolean` + // Java
	`|(?:int|float|bool)\s*\(` + // Python int(x)
	`)`)

func isSanitized(rhs string) bool { return reSanitizer.MatchString(rhs) }

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
