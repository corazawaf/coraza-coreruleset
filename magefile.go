// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/sh"
)

const (
	rulesDir             = "rules"
	testsDir             = "tests"
	crsDir               = rulesDir + "/@owasp_crs"
	crsPluginsDir        = rulesDir + "/@owasp_crs_plugins"
	licenseNumberOfLines = 9
)

// DownloadDeps downloads the OWASP CRS, OWASP CRS Plugins and the recommended OWASP Coraza configuration file
func DownloadDeps() error {
	// cleanup rules in rules/@owasp_crs directory
	if err := cleanupOldCRSRules(crsDir); err != nil {
		return err
	}
	if err := os.MkdirAll(crsDir, os.ModePerm); err != nil {
		return err
	}

	// cleanup rules in rules/@owasp_crs_plugins directory
	if err := cleanupOldCRSRules(crsPluginsDir); err != nil {
		return err
	}
	if err := os.MkdirAll(crsPluginsDir, os.ModePerm); err != nil {
		return err
	}

	// cleanup tests in tests/ directory
	if err := cleanupOldCRSTests(testsDir); err != nil {
		return err
	}

	if err := downloadCRS(); err != nil {
		return err
	}
	fmt.Printf("Updated CRS to version %q\n", crsVersion)

	for plugin, version := range crsPlugins {
		if err := downloadCRSPlugin(plugin, version); err != nil {
			return err
		}
		fmt.Printf("Updated CRS plugin %q to version %q\n", plugin, version)
	}

	if err := downloadCorazaConfig(); err != nil {
		return err
	}
	fmt.Printf("Updated Coraza config to version %q\n", corazaVersion)

	return nil
}

// downloadCorazaConfig downloads the recommended Coraza configuration file from the OWASP Coraza repository
func downloadCorazaConfig() error {
	uri := fmt.Sprintf("https://raw.githubusercontent.com/corazawaf/coraza/%s/coraza.conf-recommended", corazaVersion)
	corazaConfig, err := getDataFromURL(uri)
	if err != nil {
		return err
	}

	out, err := os.Create(filepath.Join(rulesDir, "@coraza.conf-recommended"))
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(corazaConfig)
	if err != nil {
		return err
	}

	return nil
}

// downloadCRS downloads the OWASP CRS from the CRS repository
func downloadCRS() error {
	uri := fmt.Sprintf("https://github.com/coreruleset/coreruleset/archive/%s.zip", crsVersion)

	crsZip, err := getDataFromURL(uri)
	if err != nil {
		return err
	}

	r, err := zip.NewReader(bytes.NewReader(crsZip), int64(len(crsZip)))
	if err != nil {
		return err
	}

	crsVersionStripped := strings.TrimPrefix(crsVersion, "v")

	for _, f := range r.File {
		if f.Name == fmt.Sprintf("coreruleset-%s/LICENSE", crsVersionStripped) {
			if err := copyFile(f, filepath.Join(rulesDir, "LICENSE")); err != nil {
				return err
			}
			continue
		}

		if f.Name == fmt.Sprintf("coreruleset-%s/crs-setup.conf.example", crsVersionStripped) {
			if err := copyFile(f, filepath.Join(rulesDir, "@crs-setup.conf.example")); err != nil {
				return err
			}
			continue
		}

		if f.FileInfo().IsDir() {
			continue
		}

		testPrefix := fmt.Sprintf("coreruleset-%s/tests/regression/tests", crsVersionStripped)
		if strings.HasPrefix(f.Name, testPrefix) {
			if !strings.HasSuffix(f.Name, ".yaml") {
				continue
			}

			subdir := strings.TrimPrefix(filepath.Dir(f.Name), testPrefix)
			dir := filepath.Join(testsDir, subdir)

			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return err
			}

			copyFile(f, filepath.Join(dir, filepath.Base(f.Name)))
		}

		prefix := fmt.Sprintf("coreruleset-%s/rules/", crsVersionStripped)
		if !strings.HasPrefix(f.Name, prefix) {
			continue
		}

		filename := f.Name[len(prefix):]

		if strings.HasSuffix(filename, ".example") {
			continue
		}

		fPath := filepath.Join(crsDir, filename)

		target, err := os.Create(fPath)
		if err != nil {
			return err
		}

		source, err := f.Open()
		if err != nil {
			os.Remove(fPath)
			return err
		}

		fileScanner := bufio.NewScanner(source)
		fileScanner.Split(bufio.ScanLines)

		lineNumber := 0

		for fileScanner.Scan() {
			lineNumber++
			if lineNumber <= licenseNumberOfLines {
				target.Write(fileScanner.Bytes())
				target.WriteString("\n")
				continue
			}

			text := strings.TrimSpace(fileScanner.Text())
			if len(text) == 0 || text[0] == '#' {
				continue
			}
			target.Write(fileScanner.Bytes())
			target.WriteString("\n")
		}
		source.Close()

		target.Close()
	}

	return nil
}

// downloadCRSPlugin downloads the OWASP CRS Plugin from CRS Plugin repository
func downloadCRSPlugin(crsPlugin, crsVersion string) error {
	uri := fmt.Sprintf("https://github.com/coreruleset/%s/archive/%s.zip", crsPlugin, crsVersion)

	crsPluginZip, err := getDataFromURL(uri)
	if err != nil {
		return err
	}

	r, err := zip.NewReader(bytes.NewReader(crsPluginZip), int64(len(crsPluginZip)))
	if err != nil {
		return err
	}

	crsPluginVersionStripped := strings.TrimPrefix(crsVersion, "v")

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		testPrefix := fmt.Sprintf("%s-%s/tests/regression/", crsPlugin, crsPluginVersionStripped)
		if strings.HasPrefix(f.Name, testPrefix) {
			if !strings.HasSuffix(f.Name, ".yaml") {
				continue
			}

			subdir := strings.TrimPrefix(filepath.Dir(f.Name), testPrefix)
			dir := filepath.Join(testsDir, subdir)

			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return err
			}

			copyFile(f, filepath.Join(dir, filepath.Base(f.Name)))
		}

		prefix := fmt.Sprintf("%s-%s/plugins/", crsPlugin, crsPluginVersionStripped)
		if !strings.HasPrefix(f.Name, prefix) {
			continue
		}

		filename := f.Name[len(prefix):]

		if strings.HasSuffix(filename, ".example") {
			continue
		}

		fPath := filepath.Join(crsPluginsDir, filename)

		target, err := os.Create(fPath)
		if err != nil {
			return err
		}

		source, err := f.Open()
		if err != nil {
			os.Remove(fPath)
			return err
		}

		fileScanner := bufio.NewScanner(source)
		fileScanner.Split(bufio.ScanLines)

		lineNumber := 0

		for fileScanner.Scan() {
			lineNumber++
			if lineNumber <= licenseNumberOfLines {
				target.Write(fileScanner.Bytes())
				target.WriteString("\n")
				continue
			}

			text := strings.TrimSpace(fileScanner.Text())
			if len(text) == 0 || text[0] == '#' {
				continue
			}
			target.Write(fileScanner.Bytes())
			target.WriteString("\n")
		}
		source.Close()

		target.Close()
	}

	return nil
}

func getDataFromURL(uri string) ([]byte, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

func copyFile(f *zip.File, dstPath string) error {
	source, err := f.Open()
	if err != nil {
		return err
	}

	l, err := io.ReadAll(source)
	if err != nil {
		return err
	}
	source.Close()

	if err := os.WriteFile(dstPath, l, 0666); err != nil {
		return err
	}
	return nil
}

func cleanupOldCRSRules(rulesDir string) error {
	if err := os.RemoveAll(rulesDir); err != nil {
		return err
	}
	return nil
}

func cleanupOldCRSTests(testsDir string) error {
	if err := filepath.WalkDir(testsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// tests folder contains go files related to the coraza-coreruleset repo that we don't want to remove
		if d.Name() != "tests.go" && d.Name() != "tests_test.go" && path != testsDir {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
			return filepath.SkipDir
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// Test runs the tests
func Test() error {
	return sh.RunV("go", "test", "./...")
}
