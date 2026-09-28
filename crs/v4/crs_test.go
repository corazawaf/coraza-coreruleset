package crs

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// activeSecDefaultActionRe matches an uncommented `SecDefaultAction "phase:N,..."`
// directive at the start of a line. The -nodefaultact variant must contain none
// of these: Coraza rejects a config that redefines SecDefaultAction, so the
// variant exists precisely to let consumers set their own.
var activeSecDefaultActionRe = regexp.MustCompile(`(?m)^SecDefaultAction\s+"phase:`)

func TestFSOpensCRSRule(t *testing.T) {
	f, err := FS.Open("@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("expected to open @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf, got: %v", err)
	}
	f.Close()
}

func TestWrapFSStripsAbsolutePrefix(t *testing.T) {
	_, err := FS.(subFS).ReadFile("/usr/src/github.com/myorg/myrepo/@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("expected wrapFS to strip absolute prefix, got: %v", err)
	}
}

// TestNodefaultactVariantNeutralisesSecDefaultAction guards the contract behind
// the -nodefaultact variant: @crs-setup.conf.example sets SecDefaultAction for
// phases 1–2, and the variant must comment every such active line so consumers
// can define their own without Coraza's "cannot redefine SecDefaultAction" error.
func TestNodefaultactVariantNeutralisesSecDefaultAction(t *testing.T) {
	orig, err := fs.ReadFile(FS, "@crs-setup.conf.example")
	if err != nil {
		t.Fatalf("reading @crs-setup.conf.example: %v", err)
	}
	variant, err := fs.ReadFile(FS, "@crs-setup.conf.example-nodefaultact")
	if err != nil {
		t.Fatalf("reading @crs-setup.conf.example-nodefaultact: %v", err)
	}
	if loc := activeSecDefaultActionRe.FindIndex(variant); loc != nil {
		t.Errorf("-nodefaultact variant still has an active SecDefaultAction directive at byte %d; "+
			"writeNodefaultactVariant must comment every `SecDefaultAction \"phase:...\"` line", loc[0])
	}
	if !activeSecDefaultActionRe.Match(orig) {
		t.Error("@crs-setup.conf.example unexpectedly has no active SecDefaultAction line: this test can no longer prove the variant strips one")
	}
}

func TestVersionFormat(t *testing.T) {
	if !strings.HasPrefix(Version, "v") {
		t.Fatalf("Version %q does not start with 'v'", Version)
	}
}
