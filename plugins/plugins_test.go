package plugins

import (
	"io/fs"
	"strings"
	"testing"
)

func TestFSPopulated(t *testing.T) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatalf("expected to list embedded plugins, got: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected plugins FS to contain at least one entry")
	}
}

// openOnly hides every method but Open, like an fs.FS that implements none of
// the optional interfaces. mergefs drops ReadFile when merging with such an FS,
// so Coraza's fs.ReadFile falls back to Open.
type openOnly struct{ fs.FS }

func TestWrapFSStripsAbsolutePrefix(t *testing.T) {
	for _, name := range []string{
		"/usr/src/github.com/myorg/myrepo/@owasp_plugins/wordpress-rule-exclusions-before.conf",
		// A parent directory containing `@` (as Go module cache paths do)
		// must not be mistaken for the alias.
		"/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/@owasp_plugins/wordpress-rule-exclusions-before.conf",
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
	matches, err := fs.Glob(FS, "/usr/src/github.com/myorg/myrepo/@owasp_plugins/*-before.conf")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected Glob to match embedded files once the prefix is stripped")
	}
}

// TestEveryPluginShipsItsLicense guards redistribution: each bundled plugin
// (identified by its <name>-config.conf) must come with its upstream license
// under licenses/<name>/LICENSE.
func TestEveryPluginShipsItsLicense(t *testing.T) {
	configs, err := fs.Glob(FS, "@owasp_plugins/*-config.conf")
	if err != nil {
		t.Fatalf("globbing plugin configs: %v", err)
	}
	if len(configs) == 0 {
		t.Fatal("expected at least one bundled plugin config")
	}
	for _, c := range configs {
		name := strings.TrimSuffix(strings.TrimPrefix(c, "@owasp_plugins/"), "-config.conf")
		if _, err := fs.Stat(FS, "licenses/"+name+"/LICENSE"); err != nil {
			t.Errorf("plugin %q has no licenses/%s/LICENSE: %v", name, name, err)
		}
	}
}

func TestVersionFormat(t *testing.T) {
	if !strings.HasPrefix(Version, "v") {
		t.Fatalf("Version %q does not start with 'v'", Version)
	}
}
