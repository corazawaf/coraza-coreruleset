# coraza-coreruleset/crs/v4

Embeds the **latest** [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) so it can be consumed by a [Coraza](https://github.com/corazawaf/coraza) WAF via `WithRootFS`.

For the CRS LTS line, use [`coraza-coreruleset/lts/v4`](../../lts/v4) instead.
For the Coraza `coraza.conf-recommended` file, use [`coraza-coreruleset/coraza/v3`](../../coraza/v3).

## Include alias

| Path | Description |
|---|---|
| `@owasp_crs/` | OWASP CRS rules directory |
| `@crs-setup.conf.example` | Upstream CRS setup file |
| `@crs-setup.conf.example-nodefaultact` | Same, with `SecDefaultAction` lines commented out, allowing custom ones to be set |

## Quick start

```go
import (
    "github.com/corazawaf/coraza/v3"
    crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
    corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
    "github.com/jcchavezs/mergefs"
)

func main() {
    waf, err := coraza.NewWAF(
        coraza.NewWAFConfig().
            WithDirectives(`
                Include @coraza.conf-recommended
                Include @crs-setup.conf.example
                Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
            `).
            WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)),
    )
    _ = waf; _ = err
}
```

## Runtime version

`crs.Version` exposes the bundled upstream CRS tag (e.g. `"v4.26.0"`).

## Tags

Module tags follow upstream CRS releases: `crs/v4.26.0`, `crs/v4.26.1`, …
