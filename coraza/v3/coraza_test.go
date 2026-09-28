package coraza

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// activeSecDefaultActionRe matches an uncommented `SecDefaultAction "phase:N,..."`
// directive at the start of a line.
var activeSecDefaultActionRe = regexp.MustCompile(`(?m)^SecDefaultAction\s+"phase:`)

func TestFSOpensRecommendedConfig(t *testing.T) {
	f, err := FS.Open("@coraza.conf-recommended")
	if err != nil {
		t.Fatalf("expected to open @coraza.conf-recommended, got: %v", err)
	}
	f.Close()
}

// TestRecommendedConfigHasNoActiveSecDefaultAction guards the reason this
// module ships no `-nodefaultact` variant: upstream Coraza keeps
// coraza.conf-recommended free of SecDefaultAction (those defaults live only
// in the CRS setup file). If a corazaVersion bump ever reintroduces one,
// consumers that set their own SecDefaultAction would hit Coraza's
// "redefining SecDefaultAction" error — this test surfaces that on the update
// PR so maintainers can reconsider a variant before shipping.
func TestRecommendedConfigHasNoActiveSecDefaultAction(t *testing.T) {
	data, err := fs.ReadFile(FS, "@coraza.conf-recommended")
	if err != nil {
		t.Fatalf("reading @coraza.conf-recommended: %v", err)
	}
	if loc := activeSecDefaultActionRe.FindIndex(data); loc != nil {
		t.Errorf("@coraza.conf-recommended has an active SecDefaultAction directive at byte %d; "+
			"upstream moved SecDefaultAction back into the recommended config — this module "+
			"needs a -nodefaultact variant again (see magefile DownloadCoraza)", loc[0])
	}
}

func TestVersionFormat(t *testing.T) {
	if !strings.HasPrefix(Version, "v") {
		t.Fatalf("Version %q does not start with 'v'", Version)
	}
}
