package tests

import (
	"embed"
)

// FS is am embedded filesystem containing the CoreRuleSet regression tests.
// For example, the path REQUEST-911-METHOD-ENFORCEMENT/911100.yaml tests
// for method enforcement and can be used with go-ftw for performing regression
// tests.
//
//go:embed *-*
var FS embed.FS
