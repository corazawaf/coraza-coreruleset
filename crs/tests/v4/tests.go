// Package tests exposes the OWASP CRS regression tests matching the latest CRS
// bundle (github.com/corazawaf/coraza-coreruleset/crs/v4) as an embedded
// filesystem, suitable for use with go-ftw.
//
// It is a separate module so that importing the rules does not download the
// test corpus. Its versions mirror crs/v4: use the same version for both.
package tests

import "embed"

// FS embeds the CRS regression tests under their REQUEST-<id>/ and
// RESPONSE-<id>/ subdirectories (matched by the *-* glob).
//
//go:embed *-*
var FS embed.FS
