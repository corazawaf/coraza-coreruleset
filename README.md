# Coraza Coreruleset

Coraza Coreruleset is a Go package meant to provide the [OWASP CRS](https://github.com/coreruleset/coreruleset) in an easy and consumable way to be embedded in a Go application. Alongside the unmodified CRS ruleset, the [upstream latest Coraza configuration file](https://github.com/corazawaf/coraza/blob/main/coraza.conf-recommended) is also provided.

## Available values for Include directives

The following values can be used in `Include` directives with a root filesystem that includes `coreruleset.FS`.

| Value | Description |
|---|---|
| `@coraza.conf-recommended` | Coraza recommended base configuration |
| `@crs-setup.conf.example` | OWASP CRS setup configuration example |
| `@owasp_crs/` | OWASP CRS rules directory |

## Usage

In order to use CRS, you need to load the coreruleset FileSystem:

```go
import "github.com/corazawaf/coraza-coreruleset/v4"

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
    "github.com/corazawaf/coraza-coreruleset/v4"
    "github.com/jcchavezs/mergefs"
    "github.com/jcchavezs/mergefs/io"
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
            WithRootFS(mergefs.Merge(coreruleset.FS, io.OSFS)),
    )
    // ...
}
```

## How to update to a newer CRS and Coraza config version

1. Update the `crsVersion` and `corazaVersion` constants in [`version.go`](/version.go) with the wished [CRS](https://github.com/coreruleset/coreruleset) and [Coraza](https://github.com/corazawaf/coraza) commit SHA or tags.
1. Run `go run mage.go downloadDeps`.
1. Double check the changes made under the `/rules` and `/tests` directories.
1. Commit your changes.
