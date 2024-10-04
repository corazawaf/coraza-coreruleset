// Copyright 2023 The OWASP Coraza contributors
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
	rulesDir = "rules"
	testsDir = "tests"
)

// DownloadDeps downloads the OWASP CRS and the recommended OWASP Coraza configuration file
func DownloadDeps() error {
	if err := downloadCRS(); err != nil {
		return err
	}
	fmt.Printf("Updated CRS to version %q\n", crsVersion)

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
	rulesDstDir := rulesDir + "/@owasp_crs"

	// Before downloading, we need to remove:
	// - old rules under rules/@owasp_crs
	// - all the related tests
	if err := cleanupOldCRS(rulesDstDir, testsDir); err != nil {
		return err
	}

	if err := os.MkdirAll(rulesDstDir, os.ModePerm); err != nil {
		return err
	}

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

	const licenseNumberOfLines = 9

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

		fPath := filepath.Join(rulesDstDir, filename)

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

func cleanupOldCRS(rulesDstDir, testsDir string) error {
	if err := os.RemoveAll(rulesDstDir); err != nil {
		return err
	}
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
