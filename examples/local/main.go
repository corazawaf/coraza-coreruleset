package main

import (
	"fmt"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/coraza-coreruleset"
	"github.com/yalue/merged_fs"
)

func main() {
	// First we initialize our waf and our seclang parser
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
				Include ./rule.conf
			`).
			WithRootFS(merged_fs.NewMergedFS(coreruleset.FS, OSFS{})),
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
