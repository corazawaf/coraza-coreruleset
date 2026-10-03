// Package crs embeds the latest OWASP Core Rule Set so it can be consumed by
// a Coraza WAF via WithRootFS.
//
// Rules are exposed under the @owasp_crs/ Include alias. Pair this filesystem
// with the coraza/v3 module (which provides @coraza.conf-recommended) using
// mergefs.Merge.
package crs

import (
	"embed"
	"io/fs"
	"log"
)

//go:embed rules/*
var wFS embed.FS

// FS is the embedded CRS rules filesystem. Pass it as the root FS of a Coraza
// WAF and Include rules using the @owasp_crs/ alias.
var FS fs.FS

func init() {
	rulesFS, err := fs.Sub(wFS, "rules")
	if err != nil {
		log.Fatal(err)
	}
	FS = wrapFS{rulesFS}
}
