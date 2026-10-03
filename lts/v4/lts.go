// Package lts embeds the OWASP CRS LTS line (v4.25.x) so it can be consumed
// by a Coraza WAF via WithRootFS.
//
// Rules are exposed under the @owasp_crs_lts/ Include alias so the LTS bundle
// can coexist with the latest CRS bundle (crs/v4, alias @owasp_crs/) in the
// same binary. At runtime, Include rules from exactly one bundle — CRS rule
// IDs collide between the two lines.
//
// Pair this filesystem with the coraza/v3 module (which provides
// @coraza.conf-recommended) using mergefs.Merge.
package lts

import (
	"embed"
	"io/fs"
	"log"
)

//go:embed rules/*
var wFS embed.FS

// FS is the embedded CRS LTS rules filesystem. Pass it as the root FS of a
// Coraza WAF and Include rules using the @owasp_crs_lts/ alias.
var FS fs.FS

func init() {
	rulesFS, err := fs.Sub(wFS, "rules")
	if err != nil {
		log.Fatal(err)
	}
	FS = wrapFS{rulesFS}
}
