// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

const (
	crsVersion    = "v4.23.0"
	corazaVersion = "v3.3.3"
)

var plugins = map[string]string{
	"fake-bot-plugin":                   "v1.0.0",
	"google-oauth2-plugin":              "v1.0.0",
	"drupal-rule-exclusions-plugin":     "v1.0.0",
	"wordpress-rule-exclusions-plugin":  "v1.2.0",
	"nextcloud-rule-exclusions-plugin":  "v1.5.0",
	"dokuwiki-rule-exclusions-plugin":   "v1.0.0",
	"cpanel-rule-exclusions-plugin":     "v1.0.0",
	"xenforo-rule-exclusions-plugin":    "v1.0.0",
	"phpbb-rule-exclusions-plugin":      "v1.0.0",
	"phpmyadmin-rule-exclusions-plugin": "v1.0.0",
}
