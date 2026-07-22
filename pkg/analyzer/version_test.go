package analyzer

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Version
		wantErr bool
	}{
		{name: "plain", in: "1.35.3", want: Version{1, 35, 3, ""}},
		{name: "v prefix", in: "v1.35.3", want: Version{1, 35, 3, ""}},
		{name: "major minor only", in: "1.36", want: Version{1, 36, 0, ""}},
		{name: "vendor suffix", in: "v1.35.3+sys11.1", want: Version{1, 35, 3, "+sys11.1"}},
		{name: "prerelease", in: "v1.36.0-rc.1", want: Version{1, 36, 0, "-rc.1"}},
		{name: "eks style", in: "v1.32.1-eks-1234", want: Version{1, 32, 1, "-eks-1234"}},
		{name: "whitespace", in: "  v1.35.3  ", want: Version{1, 35, 3, ""}},
		{name: "extra components ignored", in: "1.35.3.7", want: Version{1, 35, 3, ""}},

		{name: "empty", in: "", wantErr: true},
		{name: "major only", in: "1", wantErr: true},
		{name: "not a number", in: "1.x.3", wantErr: true},
		{name: "garbage", in: "latest", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseVersion(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion(%q) returned unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseVersion(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "equal", a: "1.35.3", b: "1.35.3", want: 0},
		{name: "patch older", a: "1.35.1", b: "1.35.3", want: -1},
		{name: "minor older", a: "1.35.9", b: "1.36.0", want: -1},
		{name: "major newer", a: "2.0.0", b: "1.99.99", want: 1},
		{name: "suffix ignored", a: "1.35.3+sys11", b: "1.35.3", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := MustParseVersion(tt.a), MustParseVersion(tt.b)
			if got := a.Compare(b); got != tt.want {
				t.Errorf("%s.Compare(%s) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestUpgradePath(t *testing.T) {
	tests := []struct {
		name     string
		from, to string
		want     []string
	}{
		{name: "single minor", from: "1.35.3", to: "1.36.0", want: []string{"1.36"}},
		{name: "three minors", from: "1.33.0", to: "1.36.2", want: []string{"1.34", "1.35", "1.36"}},
		{name: "patch only", from: "1.35.1", to: "1.35.9", want: nil},
		{name: "downgrade", from: "1.36.0", to: "1.35.0", want: nil},
		{name: "same version", from: "1.35.3", to: "1.35.3", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := Upgrade{From: MustParseVersion(tt.from), To: MustParseVersion(tt.to)}
			got := minorList(up.Path())
			if len(got) != len(tt.want) {
				t.Fatalf("Path() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Path()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestUpgradeCrosses(t *testing.T) {
	tests := []struct {
		name     string
		from, to string
		at       string
		want     bool
	}{
		{name: "removal in target", from: "1.35.0", to: "1.36.0", at: "1.36", want: true},
		{name: "removal before start", from: "1.35.0", to: "1.36.0", at: "1.32", want: false},
		{name: "removal after target", from: "1.35.0", to: "1.36.0", at: "1.37", want: false},
		{name: "removal mid path", from: "1.33.0", to: "1.36.0", at: "1.35", want: true},
		{name: "removal at start not crossed", from: "1.35.0", to: "1.36.0", at: "1.35", want: false},
		{name: "patch upgrade crosses nothing", from: "1.36.0", to: "1.36.4", at: "1.36", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := Upgrade{From: MustParseVersion(tt.from), To: MustParseVersion(tt.to)}
			if got := up.Crosses(MustParseVersion(tt.at)); got != tt.want {
				t.Errorf("Upgrade{%s→%s}.Crosses(%s) = %v, want %v",
					tt.from, tt.to, tt.at, got, tt.want)
			}
		})
	}
}
