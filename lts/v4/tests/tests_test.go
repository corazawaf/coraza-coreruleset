package tests

import "testing"

func TestFSPopulated(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("expected to read embedded tests root, got: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected embedded tests FS to contain at least one entry")
	}
}
