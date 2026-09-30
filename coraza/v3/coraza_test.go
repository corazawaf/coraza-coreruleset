package coraza

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// activeSecDefaultActionRe matches an uncommented, optionally indented
// `SecDefaultAction "phase:N,..."` directive.
var activeSecDefaultActionRe = regexp.MustCompile(`(?m)^[ \t]*SecDefaultAction\s+"phase:`)

func TestFSOpensRecommendedConfig(t *testing.T) {
	f, err := FS.Open("@coraza.conf-recommended")
	if err != nil {
		t.Fatalf("expected to open @coraza.conf-recommended, got: %v", err)
	}
	f.Close()
}

// openOnly hides every method but Open, like an fs.FS that implements none of
// the optional interfaces. mergefs drops ReadFile when merging with such an FS,
// so Coraza's fs.ReadFile falls back to Open.
type openOnly struct{ fs.FS }

func TestWrapFSStripsAbsolutePrefix(t *testing.T) {
	for _, name := range []string{
		"/usr/src/github.com/myorg/myrepo/@coraza.conf-recommended",
		// A parent directory containing `@` (as Go module cache paths do)
		// must not be mistaken for the alias.
		"/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/@coraza.conf-recommended",
	} {
		if _, err := fs.ReadFile(FS, name); err != nil {
			t.Errorf("ReadFile(%q): %v", name, err)
		}
		if _, err := fs.ReadFile(openOnly{FS}, name); err != nil {
			t.Errorf("ReadFile via Open(%q): %v", name, err)
		}
		if _, err := fs.Stat(FS, name); err != nil {
			t.Errorf("Stat(%q): %v", name, err)
		}
	}
}

func TestWrapFSGlobStripsAbsolutePrefix(t *testing.T) {
	matches, err := fs.Glob(FS, "/usr/src/github.com/myorg/myrepo/@coraza.conf-*")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected Glob to match embedded files once the prefix is stripped")
	}
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
