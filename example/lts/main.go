// Demonstrates loading the OWASP CRS LTS bundle together with the Coraza
// recommended configuration and an official CRS plugin.
//
// Loading rule 930 (LFI) doubles as a smoke test that data files referenced by
// the rules (e.g. `lfi-os-files.data`) resolve correctly under the
// @owasp_crs_lts/ alias.
package main

import (
	"fmt"
	"log"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	lts "github.com/corazawaf/coraza-coreruleset/lts/v4"
	"github.com/corazawaf/coraza-coreruleset/plugins"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
)

func main() {
	fmt.Printf("loading CRS LTS %s with Coraza config %s and plugins bundle %s\n",
		lts.Version, corazaconf.Version, plugins.Version)

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				Include @coraza.conf-recommended
				SecRuleEngine On
				Include @crs-setup-lts.conf.example
				Include @owasp_crs_lts/REQUEST-930-APPLICATION-ATTACK-LFI.conf
				Include @owasp_plugins/wordpress-rule-exclusions-before.conf
			`).
			WithRootFS(mergefs.Merge(lts.FS, corazaconf.FS, plugins.FS)),
	)
	if err != nil {
		log.Fatal(err)
	}

	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 12345)

	if it := tx.ProcessRequestHeaders(); it != nil {
		fmt.Printf("Transaction was interrupted with status %d\n", it.Status)
	}

	fmt.Println("Success!")
}
