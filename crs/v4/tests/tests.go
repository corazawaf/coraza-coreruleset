// Package tests exposes the OWASP CRS regression tests for the latest CRS
// bundle as an embedded filesystem, suitable for use with go-ftw.
package tests

import "embed"

// FS embeds the CRS regression tests under their REQUEST-<id>/ and
// RESPONSE-<id>/ subdirectories (matched by the *-* glob).
//
//go:embed *-*
var FS embed.FS
