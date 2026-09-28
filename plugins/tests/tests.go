// Package tests exposes the regression tests of the bundled OWASP CRS plugins
// as an embedded filesystem, suitable for use with go-ftw.
package tests

import "embed"

//go:embed *-*
var FS embed.FS
