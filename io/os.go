package io

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Copied from https://github.com/corazawaf/coraza/blob/v3/dev/internal/io/file.go

// OSFS implements fs.FS using methods on os to read from the system.
// Note that this implementation is not a compliant fs.FS, as they should only
// accept posix-style, relative paths, but as this is an internal implementation
// detail, we get the abstraction we need while being able to handle paths as
// the os package otherwise would.
// More context in: https://github.com/golang/go/issues/44279
type osFS struct{}

func (osFS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func (osFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (osFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}

func (osFS) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}

var OSFS osFS
