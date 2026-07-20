package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// Fingerprint is a stable identifier for a finding, used by baseline mode to
// recognise a previously-seen issue across runs. It is built from the rule, the
// location, and the redacted match — enough to be unique, stable across scans
// as long as the finding itself doesn't move, and safe to store (the match is
// already redacted, so no secret material lands in the baseline file).
func (f Finding) Fingerprint() string {
	h := sha256.New()
	h.Write([]byte(f.RuleID))
	h.Write([]byte{0})
	h.Write([]byte(f.File))
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(f.Line)))
	h.Write([]byte{0})
	h.Write([]byte(f.Match))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
