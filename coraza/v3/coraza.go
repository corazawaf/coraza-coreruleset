// Package coraza embeds the Coraza recommended configuration file
// (`@coraza.conf-recommended`) so it can be consumed by a Coraza WAF via
// WithRootFS.
//
// Upstream Coraza ships no SecDefaultAction in this file (SecDefaultAction
// defaults live exclusively in the CRS setup file), so it is always safe to
// combine with your own SecDefaultAction directives — no `-nodefaultact`
// variant is needed, unlike the CRS setup files in crs/v4 and lts/v4.
//
// Pair this filesystem with a CRS bundle (crs/v4 or lts/v4) using
// mergefs.Merge.
//
// The package name `coraza` collides with `github.com/corazawaf/coraza/v3`.
// When importing both, alias one of them, e.g.:
//
//	import corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
package coraza

import (
	"embed"
	"io/fs"
	"log"
)

//go:embed files/*
var wFS embed.FS

// FS exposes the Coraza recommended configuration file. Use it as the root
// filesystem of a Coraza WAF (typically merged with a CRS bundle) and Include
// `@coraza.conf-recommended`.
var FS fs.FS

func init() {
	sub, err := fs.Sub(wFS, "files")
	if err != nil {
		log.Fatal(err)
	}
	FS = wrapFS{sub.(subFS)}
}
