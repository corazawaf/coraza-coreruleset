package plugins

import (
	"strings"
	"testing"
)

func TestFSPopulated(t *testing.T) {
	sub, ok := FS.(subFS)
	if !ok {
		t.Fatal("expected FS to satisfy subFS")
	}
	entries, err := sub.ReadDir(".")
	if err != nil {
		t.Fatalf("expected to list embedded plugins, got: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected plugins FS to contain at least one entry")
	}
}

func TestVersionFormat(t *testing.T) {
	if !strings.HasPrefix(Version, "v") {
		t.Fatalf("Version %q does not start with 'v'", Version)
	}
}
