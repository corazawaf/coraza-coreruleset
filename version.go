// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

const (
	crsVersion    = "v4.15.0"
	corazaVersion = "v3.3.3"
	crsVersion    = "v4.14.0"
)

var crsPlugins = map[string]string{
	"wordpress-rule-exclusions-plugin": "v1.1.0",
}
