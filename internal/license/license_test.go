package license

import (
	"testing"

	"github.com/malandas/andas/internal/finding"
)

func TestClassify(t *testing.T) {
	cases := map[string]Risk{
		"MIT": Permissive, "Apache-2.0": Permissive, "BSD-3-Clause": Permissive, "ISC": Permissive,
		"GPL-3.0": Strong, "AGPL-3.0": Strong, "GPL-2.0-only": Strong,
		"LGPL-2.1": Weak, "MPL-2.0": Weak,
		"": Unknown, "UNLICENSED": Unknown, "Frobnicate-1.0": Unknown,
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSeverityDependsOnProprietary(t *testing.T) {
	// Strong copyleft is HIGH for a proprietary product, LOW for an OSS one.
	if Strong.Severity(true) != finding.SevHigh {
		t.Error("strong copyleft in a proprietary product should be HIGH")
	}
	if Strong.Severity(false) != finding.SevLow {
		t.Error("strong copyleft in an OSS project should be LOW")
	}
	// A missing license is a legal risk regardless.
	if Unknown.Severity(false) != finding.SevMedium {
		t.Error("unknown license should be MEDIUM either way")
	}
}
