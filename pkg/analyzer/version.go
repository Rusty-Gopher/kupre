package analyzer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Version is a Kubernetes semantic version. Only major and minor participate in
// upgrade-path reasoning; patch is retained for display.
type Version struct {
	Major int
	Minor int
	Patch int
	// Pre holds any prerelease/build suffix, e.g. "-eks-1234" or "+vendor.1".
	Pre string
}

// ParseVersion parses a Kubernetes version string. It tolerates the forms
// commonly reported by the API server: "v1.35.3", "1.35", "v1.35.3+sys11.1"
// and "v1.35.3-rc.0".
func ParseVersion(s string) (Version, error) {
	var v Version
	raw := strings.TrimSpace(s)
	if raw == "" {
		return v, fmt.Errorf("empty version string")
	}
	raw = strings.TrimPrefix(raw, "v")

	// Split off any prerelease or build metadata before parsing numbers.
	if i := strings.IndexAny(raw, "-+"); i >= 0 {
		v.Pre = raw[i:]
		raw = raw[:i]
	}

	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return v, fmt.Errorf("version %q: want at least major.minor", s)
	}
	nums := make([]int, 0, 3)
	for i, p := range parts {
		if i > 2 {
			break
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return v, fmt.Errorf("version %q: component %q is not a number", s, p)
		}
		if n < 0 {
			return v, fmt.Errorf("version %q: negative component", s)
		}
		nums = append(nums, n)
	}
	v.Major, v.Minor = nums[0], nums[1]
	if len(nums) > 2 {
		v.Patch = nums[2]
	}
	return v, nil
}

// MustParseVersion parses s and panics on failure. For use in tests and static
// package-level data only.
func MustParseVersion(s string) Version {
	v, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}

// String renders the version as vMAJOR.MINOR.PATCH.
func (v Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// MinorString renders just the release line, e.g. "1.35".
func (v Version) MinorString() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// Compare returns -1 if v sorts before o, 1 if after, and 0 if equal. The
// prerelease suffix is ignored.
func (v Version) Compare(o Version) int {
	for _, p := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// LessThan reports whether v is strictly older than o.
func (v Version) LessThan(o Version) bool { return v.Compare(o) < 0 }

// AtLeast reports whether v is o or newer.
func (v Version) AtLeast(o Version) bool { return v.Compare(o) >= 0 }

// MinorDistance returns how many minor releases separate v from o, assuming the
// same major version. The result is negative when o is older than v.
func (v Version) MinorDistance(o Version) int { return o.Minor - v.Minor }

// MarshalJSON renders the version as a string for report output.
func (v Version) MarshalJSON() ([]byte, error) { return json.Marshal(v.String()) }

// UnmarshalJSON parses a version from its string form.
func (v *Version) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := ParseVersion(s)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

// Path returns every minor release strictly after u.From up to and including
// u.To. These are the releases whose breaking changes apply to the upgrade.
// It returns nil when the target is not newer than the current version.
func (u Upgrade) Path() []Version {
	if !u.From.LessThan(u.To) || u.From.Major != u.To.Major {
		return nil
	}
	var out []Version
	for m := u.From.Minor + 1; m <= u.To.Minor; m++ {
		out = append(out, Version{Major: u.From.Major, Minor: m})
	}
	return out
}

// Crosses reports whether the upgrade passes through the given release, i.e.
// whether a change landing in that release applies to this upgrade. Comparison
// is at minor-release granularity: a change in 1.36 applies to an upgrade from
// 1.35.3 to 1.36.0, but not to one from 1.36.0 to 1.36.4.
func (u Upgrade) Crosses(v Version) bool {
	from := Version{Major: u.From.Major, Minor: u.From.Minor}
	to := Version{Major: u.To.Major, Minor: u.To.Minor}
	at := Version{Major: v.Major, Minor: v.Minor}
	return from.LessThan(at) && !to.LessThan(at)
}

// Skew returns the number of minor versions the upgrade spans.
func (u Upgrade) Skew() int { return u.From.MinorDistance(u.To) }
