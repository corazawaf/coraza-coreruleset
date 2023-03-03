package tests

import "testing"

func TestTests(t *testing.T) {
	_, err := FS.Open("REQUEST-911-METHOD-ENFORCEMENT/911100.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
