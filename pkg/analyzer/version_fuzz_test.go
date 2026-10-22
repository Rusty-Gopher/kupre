package analyzer

import "testing"

// FuzzParseVersion: --target-version is user input. Parsing must never panic,
// and anything it accepts must round-trip through String.
func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"1.37.0", "v1.36", "1.35.3-eks-1", "1.2.3+k3s1", "", "1.", "x.y", "1.99999999999999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)
		if err != nil {
			return
		}
		again, err := ParseVersion(v.String())
		if err != nil {
			t.Fatalf("ParseVersion(%q) = %v, but its String %q does not parse: %v", s, v, v.String(), err)
		}
		if again.Compare(v) != 0 {
			t.Fatalf("round trip changed %q: %v -> %v", s, v, again)
		}
	})
}
