// Demonstrates loading the latest OWASP CRS bundle together with the Coraza
// recommended configuration in a Coraza WAF.
package main

import (
	"fmt"
	"log"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
)

func main() {
	fmt.Printf("loading CRS %s with Coraza config %s\n", crs.Version, corazaconf.Version)

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				Include @coraza.conf-recommended
				SecRuleEngine On
				Include @crs-setup.conf.example
				Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
			`).
			WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)),
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
