// Package plugins embeds official OWASP CRS plugins so they can be consumed
// by a Coraza WAF via WithRootFS.
//
// Rules are exposed under the @owasp_plugins/ Include alias. The set of
// bundled plugins and their upstream versions is tracked in
// `plugins/versions.json`.
//
// This bundle is intentionally decoupled from any specific CRS version —
// merge it with whichever CRS bundle (crs/v4 or lts/v4) suits your needs.
package plugins

import (
	"embed"
	"io/fs"
	"log"
)

//go:embed files/*
var wFS embed.FS

// FS is the embedded plugins filesystem. Pass it as the root FS of a Coraza
// WAF (typically merged with a CRS bundle) and Include rules using the
// @owasp_plugins/ alias.
var FS fs.FS

func init() {
	sub, err := fs.Sub(wFS, "files")
	if err != nil {
		log.Fatal(err)
	}
	FS = wrapFS{sub}
}
