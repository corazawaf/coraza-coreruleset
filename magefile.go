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
	"github.com/magefile/mage/sh"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func DownloadCRS() error {
	rulesDir := "rules"
	rulesDstDir := rulesDir + "/@owasp_crs"
	if err := os.MkdirAll(rulesDstDir, os.ModePerm); err != nil {
		return err
	}

	testsDir := "tests"

	uri := fmt.Sprintf("https://github.com/coreruleset/coreruleset/archive/%s.zip", crsVersion)

	res, err := http.Get(uri)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	crsZip, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	r, err := zip.NewReader(bytes.NewReader(crsZip), int64(len(crsZip)))
	if err != nil {
		return err
	}

	const licenseNumberOfLines = 9

	for _, f := range r.File {
		if f.Name == fmt.Sprintf("coreruleset-%s/LICENSE", crsVersion) {
			if err := copyFile(f, filepath.Join(rulesDir, "LICENSE")); err != nil {
				return err
			}
			continue
		}

		if f.Name == fmt.Sprintf("coreruleset-%s/crs-setup.conf.example", crsVersion) {
			if err := copyFile(f, filepath.Join(rulesDir, "@crs-setup.conf.example")); err != nil {
				return err
			}
			continue
		}

		if f.FileInfo().IsDir() {
			continue
		}

		testPrefix := fmt.Sprintf("coreruleset-%s/tests/regression/tests", crsVersion)
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

		prefix := fmt.Sprintf("coreruleset-%s/rules/", crsVersion)
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
			defer os.Remove(fPath)
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

func Test() error {
	return sh.RunV("go", "test", "./...")
}
