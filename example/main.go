package main

import (
	"fmt"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
)

func main() {
	// First we initialize our waf and our seclang parser
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives("Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf").
			WithRootFS(coreruleset.FS),
	)
	// Now we parse our rules
	if err != nil {
		fmt.Println(err)
	}

	// Then we create a transaction and assign some variables
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 12345)

	// Finally we process the request headers phase, which may return an interruption
	if it := tx.ProcessRequestHeaders(); it != nil {
		fmt.Printf("Transaction was interrupted with status %d\n", it.Status)
	}

	fmt.Println("Success!")
}
