// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

// Upstream version pins for the mage downloaders. Watched by Renovate
// (see /renovate.json customManagers).
//
// After a successful download, each downloader regenerates the corresponding
// subpackage's `version.go` so the runtime `Version` constant stays in lockstep
// with what's embedded.
const (
	// crsVersion is the OWASP CRS upstream tag bundled by /crs/v4.
	crsVersion = "v4.26.0"
	// ltsVersion is the OWASP CRS LTS upstream tag bundled by /lts/v4.
	// LTS cadence: quarterly v4.25.x patches through Q3 2027.
	ltsVersion = "v4.25.0"
	// corazaVersion is the Coraza upstream tag whose `coraza.conf-recommended`
	// is bundled by /coraza/v3.
	corazaVersion = "v3.5.0"
)
