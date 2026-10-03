// Package tests exposes the regression tests of the OWASP CRS plugins bundled
// by github.com/corazawaf/coraza-coreruleset/plugins as an embedded
// filesystem, suitable for use with go-ftw.
//
// It is a separate module so that importing the plugins does not download the
// test corpus. Its versions mirror the plugins module: use the same version
// for both.
package tests

import "embed"

//go:embed *-*
var FS embed.FS
