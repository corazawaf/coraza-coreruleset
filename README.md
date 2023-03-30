# Coraza Coreruleset

## Usage

In order to use CRS, you need to load the coreruleset FileSystem:

```go
import "github.com/corazawaf/coraza-coreruleset"

func main() {
    // ...
    waf, err := coraza.NewWAF(
        coraza.NewWAFConfig().
            WithDirectives("Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf").
            WithRootFS(coreruleset.FS),
    )
    // ...
}
```

You can also combine both CRS and your local files by combining the filesystems:

```go
import (
    "github.com/corazawaf/coraza-coreruleset"
    "github.com/corazawaf/coraza-coreruleset/io"
    "github.com/yalue/merged_fs"
 )

// ...

func main() {
    // ...
    waf, err := coraza.NewWAF(
        coraza.NewWAFConfig().
            WithDirectives(`
                Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
                Include my/local/rule.conf
            `).
            WithRootFS(merged_fs.NewMergedFS(coreruleset.FS, io.OSFS)),
    )
    // ...
}
```

## How to update to a newer CRS version

1. Update the `crsVersion` constant in [`version.go`](/version.go) with the wished [CRS](https://github.com/coreruleset/coreruleset) commit SHA. 
2. Run `mage downloadCRS`. 
3. Commit your changes.
