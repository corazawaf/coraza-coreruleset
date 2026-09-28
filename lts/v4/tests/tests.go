// Package tests exposes the OWASP CRS LTS regression tests for the LTS bundle
// as an embedded filesystem, suitable for use with go-ftw.
package tests

import "embed"

//go:embed *-*
var FS embed.FS
