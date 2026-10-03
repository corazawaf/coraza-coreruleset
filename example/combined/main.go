// Embeds every bundle once (latest CRS, CRS LTS, the official plugins and the
// Coraza recommended configuration) and builds several WAFs from the same root
// FS, e.g. to pick the CRS line or the plugins at runtime without rebuilding.
//
// CRS rule IDs overlap between the two lines, so each WAF includes the rules
// of only one of them.
package main

import (
	"fmt"
	"log"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	lts "github.com/corazawaf/coraza-coreruleset/lts/v4"
	"github.com/corazawaf/coraza-coreruleset/plugins"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
)

var rootFS = mergefs.Merge(crs.FS, lts.FS, plugins.FS, corazaconf.FS)

const (
	harmless = "/?q=hello"
	attack   = "/?id=1%27%20OR%201%3D1--" // SQL injection: 1' OR 1=1--
	// The same payload in a WordPress comment reply, whose content the
	// WordPress plugin excludes from CRS inspection. The exclusion runs in the
	// same phase as the CRS rules it targets, so it only works when the plugin
	// is included before them.
	wpReply = "/wp-admin/admin-ajax.php?action=replyto-comment&content=1%27%20OR%201%3D1--"
)

type scenario struct {
	name       string
	directives string
}

var scenarios = []scenario{
	{"latest", `
		Include @coraza.conf-recommended
		SecRuleEngine On
		Include @crs-setup.conf.example
		Include @owasp_crs/*.conf
	`},
	{"lts", `
		Include @coraza.conf-recommended
		SecRuleEngine On
		Include @crs-setup-lts.conf.example
		Include @owasp_crs_lts/*.conf
	`},
	{"latest with custom SecDefaultAction", `
		Include @coraza.conf-recommended
		SecRuleEngine On
		# The -nodefaultact setup leaves SecDefaultAction to you. CRS's blocking
		# rule takes its status from here, so blocked requests now get a 418.
		Include @crs-setup.conf.example-nodefaultact
		SecDefaultAction "phase:1,log,auditlog,pass,status:418"
		SecDefaultAction "phase:2,log,auditlog,pass,status:418"
		Include @owasp_crs/*.conf
	`},
	{"lts with the WordPress plugin", `
		Include @coraza.conf-recommended
		SecRuleEngine On
		Include @crs-setup-lts.conf.example
		# Plugin order: config, before, CRS rules, after (none for WordPress).
		Include @owasp_plugins/wordpress-rule-exclusions-config.conf
		Include @owasp_plugins/wordpress-rule-exclusions-before.conf
		Include @owasp_crs_lts/*.conf
	`},
}

func newWAF(directives string) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(rootFS).
		WithDirectives(directives))
}

// send runs a GET request for uri through the WAF and returns the
// interruption, or nil if the request was allowed.
func send(waf coraza.WAF, uri string) *types.Interruption {
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	tx.ProcessConnection("127.0.0.1", 12345, "127.0.0.1", 8080)
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddRequestHeader("User-Agent", "coraza-example")
	tx.AddRequestHeader("Accept", "*/*")
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		log.Fatal(err)
	}
	return it
}

func main() {
	fmt.Printf("CRS %s, CRS LTS %s, plugins %s, Coraza config %s\n",
		crs.Version, lts.Version, plugins.Version, corazaconf.Version)

	for _, s := range scenarios {
		waf, err := newWAF(s.directives)
		if err != nil {
			log.Fatalf("%s: %v", s.name, err)
		}
		fmt.Printf("\n%s\n", s.name)
		for _, uri := range []string{harmless, attack, wpReply} {
			if it := send(waf, uri); it != nil {
				fmt.Printf("  GET %s: blocked (%d) by rule %d\n", uri, it.Status, it.RuleID)
			} else {
				fmt.Printf("  GET %s: allowed\n", uri)
			}
		}
	}
}
