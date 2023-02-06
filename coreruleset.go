package coreruleset

import (
	"embed"
	"io/fs"
	"log"
)

//go:embed rules/*
var wFS embed.FS
var FS fs.FS

func init() {
	var err error
	FS, err = fs.Sub(wFS, "rules")
	if err != nil {
		log.Fatal(err)
	}
}
