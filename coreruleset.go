package coreruleset

import (
	"embed"
	"io/fs"
	"log"
	"strings"
)

// subFS is the interface that contains the methods that are used by
// `fs.subFS`
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

// wrapFS is a wrapper around a subFS that removes the absolute path prefix
// from the `name` argument in the ReadFile method.
// The rationale is that the coraza parser when asked to load the files
// invoked by `Include` will prepend the dir path of the parent file.
// For example if you aim to load directives from `my-file.conf which contains`:
//
//	`Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf`
//
// the way the parser will load the REQUEST-911-METHOD-ENFORCEMENT.conf file
// will depend on how the config was passed on the `WithDirectivesFromFile` method:
//   - `my-file.conf`: the dir is "" and hence it will call the RootFS to load
//     `@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf`
//   - `../my-file.conf`: the dir is `..` and hence it will call the RootFS to load
//     `../@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf` which can't be resolved
//     because CRS filesyste only holds references to `@owasp_crs“.
//   - `/abs-path/my-file.conf`: the dir is `/abs-path` and hence it will call the RootFS
//     to load `/abs-path/@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf` which can't
//     be resolved because CRS filesystem only holds references to `@owasp_crs`.
//
// The `@owasp_crs` folder is supposed to be ubiqutous as long as you include the coreruleset
// in the same way absolute path is.
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
