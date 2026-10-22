package version

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		ver  string
		want Status
	}{
		{"8.2.34", StatusVulnerable}, // one below fix
		{"8.2.35", StatusPatched},    // exact fix
		{"8.2.36", StatusPatched},    // above fix
		{"8.3.35", StatusVulnerable},
		{"8.3.36", StatusPatched},
		{"8.4.26", StatusVulnerable},
		{"8.4.27", StatusPatched},
		{"8.5.11", StatusVulnerable},
		{"8.5.12", StatusPatched},
		{"8.1.28", StatusEOL},
		{"7.4.33", StatusEOL},
		{"5.6.40", StatusEOL},
		{"9.0.0", StatusUnknown},
		{"", StatusUnknown},
		{"notaversion", StatusUnknown},
	}

	for _, tc := range cases {
		got := Classify(tc.ver)
		if got.Status != tc.want {
			t.Errorf("Classify(%q) = %v, want %v (note: %s)", tc.ver, got.Status, tc.want, got.Note)
		}
	}
}

func TestExtractFromBanner(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"PHP/8.3.35", "8.3.35"},
		{"Apache/2.4 PHP/8.2.34 OpenSSL/3.0", "8.2.34"},
		{"nginx", ""},
		{"X-Powered-By: PHP 8.5.11", "8.5.11"},
	}
	for _, tc := range cases {
		got := ExtractFromBanner(tc.input)
		if got != tc.want {
			t.Errorf("ExtractFromBanner(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
