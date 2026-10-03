package coraza

import (
	"io/fs"
	"strings"
)

// wrapFS wraps the embedded filesystem and removes any path prefix before the
// alias from the names passed to all of its methods, so absolute-path Include
// resolution by the Coraza seclang parser still finds the embedded
// `@coraza.conf-recommended*` files. The prefix is stripped in every method, not just
// ReadFile: mergefs only exposes ReadFile when all merged filesystems
// implement it, so merging with an Open-only fs.FS makes fs.ReadFile fall
// back to Open.
type wrapFS struct {
	fs fs.FS
}

func (w wrapFS) Open(name string) (fs.File, error) {
	return w.fs.Open(trimToAlias(name))
}

func (w wrapFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(w.fs, trimToAlias(name))
}

func (w wrapFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(w.fs, trimToAlias(name))
}

func (w wrapFS) Glob(pattern string) ([]string, error) {
	return fs.Glob(w.fs, trimToAlias(pattern))
}

// trimToAlias returns name starting at its last path segment that begins with
// `@` (an embedded alias such as `@owasp_crs/`), or name unchanged if there is
// none. Anchoring on a segment start rather than on the first `@` keeps parent
// directories that merely contain `@` (e.g. `/src/app@v2/`, Go module cache
// paths) from being mistaken for the alias.
func trimToAlias(name string) string {
	idx := strings.LastIndex(name, "/@")
	if idx == -1 {
		return name
	}
	return name[idx+1:]
}
