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
)

func DownloadCRS() error {
	dstDir := "./rules/@owasp_crs"
	if err := os.MkdirAll(dstDir, os.ModePerm); err != nil {
		return err
	}

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

	for _, f := range r.File {
		prefix := fmt.Sprintf("coreruleset-%s/rules/", crsVersion)
		if !strings.HasPrefix(f.Name, prefix) {
			continue
		}

		if f.FileInfo().IsDir() {
			continue
		}

		filename := f.Name[len(prefix):]

		if strings.HasSuffix(filename, ".example") {
			continue
		}

		fPath := filepath.Join(dstDir, filename)

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
		for fileScanner.Scan() {
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
