// Demonstrates bundling BOTH the latest OWASP CRS and the LTS CRS into the
// same binary and choosing between them at runtime via a flag.
//
// The two bundles can coexist because they expose distinct Include aliases
// (@owasp_crs/ vs @owasp_crs_lts/) — but their rule IDs collide (e.g.
// id:930100 exists in both lines), so a single Coraza WAF must Include rules
// from exactly one bundle at a time.
//
// Run as:
//
//	go run .          # default: latest CRS
//	go run . --lts    # same binary, LTS rules
//
// Bundling both adds ~750 KB compared to picking one at build time; the
// trade-off is the ability to ship a single binary that operators can switch
// without rebuilding.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	lts "github.com/corazawaf/coraza-coreruleset/lts/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
)

func main() {
	useLTS := flag.Bool("lts", false, "use the CRS LTS bundle instead of the latest")
	flag.Parse()

	var (
		rulesFS fs.FS
		alias   string
		version string
	)
	if *useLTS {
		rulesFS, alias, version = lts.FS, "@owasp_crs_lts", lts.Version
	} else {
		rulesFS, alias, version = crs.FS, "@owasp_crs", crs.Version
	}

	fmt.Printf("loading CRS %s with Coraza config %s\n", version, corazaconf.Version)

	directives := fmt.Sprintf(`
		Include @coraza.conf-recommended
		SecRuleEngine On
		SecDefaultAction "phase:1,log,auditlog,pass"
		SecDefaultAction "phase:2,log,auditlog,pass"
		Include %s/REQUEST-911-METHOD-ENFORCEMENT.conf
	`, alias)

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(directives).
			WithRootFS(mergefs.Merge(rulesFS, corazaconf.FS)),
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
