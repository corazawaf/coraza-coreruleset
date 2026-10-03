package lts

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// activeSecDefaultActionRe matches an uncommented, optionally indented
// `SecDefaultAction "phase:N,..."` directive. The -nodefaultact variant must contain none
// of these: Coraza rejects a config that redefines SecDefaultAction, so the
// variant exists precisely to let consumers set their own.
var activeSecDefaultActionRe = regexp.MustCompile(`(?m)^[ \t]*SecDefaultAction\s+"phase:`)

func TestFSOpensLTSRule(t *testing.T) {
	f, err := FS.Open("@owasp_crs_lts/REQUEST-911-METHOD-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("expected to open @owasp_crs_lts/REQUEST-911-METHOD-ENFORCEMENT.conf, got: %v", err)
	}
	f.Close()
}

// openOnly hides every method but Open, like an fs.FS that implements none of
// the optional interfaces. mergefs drops ReadFile when merging with such an FS,
// so Coraza's fs.ReadFile falls back to Open.
type openOnly struct{ fs.FS }

func TestWrapFSStripsAbsolutePrefix(t *testing.T) {
	for _, name := range []string{
		"/usr/src/github.com/myorg/myrepo/@owasp_crs_lts/REQUEST-911-METHOD-ENFORCEMENT.conf",
		// A parent directory containing `@` (as Go module cache paths do)
		// must not be mistaken for the alias.
		"/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/@owasp_crs_lts/REQUEST-911-METHOD-ENFORCEMENT.conf",
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
	matches, err := fs.Glob(FS, "/usr/src/github.com/myorg/myrepo/@owasp_crs_lts/*.conf")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected Glob to match embedded files once the prefix is stripped")
	}
}

// TestNodefaultactVariantNeutralisesSecDefaultAction guards the contract behind
// the -nodefaultact variant: the LTS setup file sets SecDefaultAction for phases
// 1–2, and the variant must comment every such active line so consumers can
// define their own without Coraza's "cannot redefine SecDefaultAction" error.
//
// The LTS setup is aliased @crs-setup-lts.conf.example (not @crs-setup.conf.example)
// so it can coexist with the latest line's setup when both bundles are merged.
func TestNodefaultactVariantNeutralisesSecDefaultAction(t *testing.T) {
	orig, err := fs.ReadFile(FS, "@crs-setup-lts.conf.example")
	if err != nil {
		t.Fatalf("reading @crs-setup-lts.conf.example: %v", err)
	}
	variant, err := fs.ReadFile(FS, "@crs-setup-lts.conf.example-nodefaultact")
	if err != nil {
		t.Fatalf("reading @crs-setup-lts.conf.example-nodefaultact: %v", err)
	}
	if loc := activeSecDefaultActionRe.FindIndex(variant); loc != nil {
		t.Errorf("-nodefaultact variant still has an active SecDefaultAction directive at byte %d; "+
			"writeNodefaultactVariant must comment every `SecDefaultAction \"phase:...\"` line", loc[0])
	}
	if !activeSecDefaultActionRe.Match(orig) {
		t.Error("@crs-setup-lts.conf.example unexpectedly has no active SecDefaultAction line: this test can no longer prove the variant strips one")
	}
}

// TestSetupFileIsLTSAliased ensures the LTS bundle does NOT expose the shared
// @crs-setup.conf.example name. If it did, merging crs/v4 and lts/v4 into one
// root FS would collide on that path (mergefs returns the first match), making
// the setup un-selectable — the exact bug the @crs-setup-lts rename fixes.
func TestSetupFileIsLTSAliased(t *testing.T) {
	if f, err := FS.Open("@crs-setup.conf.example"); err == nil {
		f.Close()
		t.Error("LTS FS exposes @crs-setup.conf.example; it must only expose @crs-setup-lts.conf.example so it can coexist with the latest CRS bundle")
	}
}

func TestVersionFormat(t *testing.T) {
	if !strings.HasPrefix(Version, "v") {
		t.Fatalf("Version %q does not start with 'v'", Version)
	}
}
