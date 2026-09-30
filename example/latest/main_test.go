package main

import "testing"

func TestExample(t *testing.T) {
	waf, err := newWAF()
	if err != nil {
		t.Fatal(err)
	}
	if it := send(waf, harmless); it != nil {
		t.Errorf("harmless request blocked by rule %d", it.RuleID)
	}
	if it := send(waf, attack); it == nil || it.Status != 403 {
		t.Errorf("attack not blocked with 403: %+v", it)
	}
}
