// Package tests exposes the OWASP CRS LTS regression tests matching the LTS
// bundle (github.com/corazawaf/coraza-coreruleset/lts/v4) as an embedded
// filesystem, suitable for use with go-ftw.
//
// It is a separate module so that importing the rules does not download the
// test corpus. Its versions mirror lts/v4: use the same version for both.
package tests

import "embed"

//go:embed *-*
var FS embed.FS
