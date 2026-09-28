package plugins

import (
	"io/fs"
	"strings"
)

type subFS interface {
	Open(name string) (fs.File, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	ReadFile(name string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// wrapFS strips any leading path prefix from `name` before the first `@`,
// so absolute-path Include resolution by the Coraza seclang parser still
// finds the embedded `@owasp_plugins/*` files.
type wrapFS struct {
	subFS
}

func (wfs wrapFS) ReadFile(name string) ([]byte, error) {
	idx := strings.Index(name, "@")
	if idx != -1 {
		name = name[idx:]
	}
	return wfs.subFS.ReadFile(name)
}
