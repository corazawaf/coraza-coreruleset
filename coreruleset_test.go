package coreruleset

import "testing"

func TestRules(t *testing.T) {
	_, err := FS.Open("@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
