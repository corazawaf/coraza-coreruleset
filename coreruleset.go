package coreruleset

import (
	"embed"
	"io/fs"
	"log"
	"strings"
)

// subFS is the interface that contains the methods that are used by
// fs.subFS
type subFS interface {
	Open(name string) (fs.File, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	ReadFile(name string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

//go:embed rules/*
var wFS embed.FS
var FS fs.FS

func init() {
	rulesFS, err := fs.Sub(wFS, "rules")
	if err != nil {
		log.Fatal(err)
	}
	FS = wrapFS{rulesFS.(subFS)}
}

// wrapFS is a wrapper around a subFS that removes the prefix from the
// name argument to the methods. The rationale is that the coraza parser
// will try to resolve an absolute path seeking for the trailing / but
// the coreruleset files are invoked as @owasp_crs and are supposed to
// be ubiqutous as long as you include the coreruleset filesystem.
type wrapFS struct {
	delegate subFS
}

func (wfs wrapFS) Open(name string) (fs.File, error) {
	idx := strings.Index(name, "@")
	if idx != -1 {
		name = name[idx:]
	}

	return wfs.delegate.Open(name)
}

func (wfs wrapFS) ReadDir(name string) ([]fs.DirEntry, error) {
	idx := strings.Index(name, "@")
	if idx != -1 {
		name = name[idx:]
	}
	return wfs.delegate.ReadDir(name)
}

func (wfs wrapFS) ReadFile(name string) ([]byte, error) {
	idx := strings.Index(name, "@")
	if idx != -1 {
		name = name[idx:]
	}

	return wfs.delegate.ReadFile(name)
}

func (wfs wrapFS) Glob(pattern string) ([]string, error) {
	return wfs.delegate.Glob(pattern)
}
