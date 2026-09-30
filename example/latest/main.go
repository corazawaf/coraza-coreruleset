// Loads the full latest OWASP CRS together with the Coraza recommended
// configuration, then shows that a harmless request passes while an attack is
// blocked.
package main

import (
	"fmt"
	"log"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
)

const (
	harmless = "/?q=hello"
	attack   = "/?id=1%27%20OR%201%3D1--" // SQL injection: 1' OR 1=1--
)

func newWAF() (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)).
		WithDirectives(`
			Include @coraza.conf-recommended
			SecRuleEngine On
			Include @crs-setup.conf.example
			Include @owasp_crs/*.conf
		`))
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
	fmt.Printf("CRS %s, Coraza config %s\n", crs.Version, corazaconf.Version)

	waf, err := newWAF()
	if err != nil {
		log.Fatal(err)
	}
	for _, uri := range []string{harmless, attack} {
		if it := send(waf, uri); it != nil {
			fmt.Printf("GET %s: blocked (%d) by rule %d\n", uri, it.Status, it.RuleID)
		} else {
			fmt.Printf("GET %s: allowed\n", uri)
		}
	}
}
