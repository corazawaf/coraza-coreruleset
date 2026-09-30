package main

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/corazawaf/coraza-coreruleset/plugins"
)

// TestScenarios checks what the example prints: the status each scenario
// returns for each request, 0 meaning allowed.
func TestScenarios(t *testing.T) {
	want := map[string]map[string]int{
		"latest":                              {harmless: 0, attack: 403, wpReply: 403},
		"lts":                                 {harmless: 0, attack: 403, wpReply: 403},
		"latest with custom SecDefaultAction": {harmless: 0, attack: 418, wpReply: 418},
		"lts with the WordPress plugin":       {harmless: 0, attack: 403, wpReply: 0},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			waf, err := newWAF(s.directives)
			if err != nil {
				t.Fatal(err)
			}
			for uri, status := range want[s.name] {
				got := 0
				if it := send(waf, uri); it != nil {
					got = it.Status
				}
				if got != status {
					t.Errorf("GET %s: got status %d, want %d", uri, got, status)
				}
			}
		})
	}
}

// TestStockSetupRejectsCustomDefaults shows why the -nodefaultact setup exists:
// the stock setup already sets SecDefaultAction, and Coraza refuses a second
// one for the same phase once a rule follows.
func TestStockSetupRejectsCustomDefaults(t *testing.T) {
	_, err := newWAF(`
		Include @crs-setup.conf.example
		SecDefaultAction "phase:1,log,auditlog,pass,status:418"
		Include @owasp_crs/*.conf
	`)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("expected a SecDefaultAction redefinition error, got: %v", err)
	}
}

// TestEveryPluginLoads loads each bundled plugin, in the standard plugin
// order, with each CRS line.
func TestEveryPluginLoads(t *testing.T) {
	configs, err := fs.Glob(plugins.FS, "@owasp_plugins/*-config.conf")
	if err != nil || len(configs) == 0 {
		t.Fatalf("no plugins found: %v", err)
	}
	lines := map[string]string{
		"latest": "Include @crs-setup.conf.example\nInclude @owasp_crs/*.conf",
		"lts":    "Include @crs-setup-lts.conf.example\nInclude @owasp_crs_lts/*.conf",
	}
	for _, config := range configs {
		name := strings.TrimSuffix(config, "-config.conf")
		after := ""
		if _, err := fs.Stat(plugins.FS, name+"-after.conf"); err == nil {
			after = "Include " + name + "-after.conf"
		}
		for line, crsRules := range lines {
			t.Run(fmt.Sprintf("%s/%s", strings.TrimPrefix(name, "@owasp_plugins/"), line), func(t *testing.T) {
				setup, rules, _ := strings.Cut(crsRules, "\n")
				_, err := newWAF(strings.Join([]string{
					setup,
					"Include " + name + "-config.conf",
					"Include " + name + "-before.conf",
					rules,
					after,
				}, "\n"))
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
