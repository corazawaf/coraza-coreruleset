package main

import (
	"io/fs"
	"os"
	"path/filepath"
)

// OSFS implements fs.FS using methods on os to read from the system.
// Note that this implementation is not a compliant fs.FS, as they should only
// accept posix-style, relative paths, but as this is an internal implementation
// detail, we get the abstraction we need while being able to handle paths as
// the os package otherwise would.
// More context in: https://github.com/golang/go/issues/44279
type OSFS struct{}

func (OSFS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func (OSFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (OSFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}

func (OSFS) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}
