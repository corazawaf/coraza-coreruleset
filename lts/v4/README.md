# coraza-coreruleset/lts/v4

Embeds the [OWASP CRS LTS line](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/) (v4.25.x — quarterly bug-fix + security patches through Q3 2027).

For the latest CRS, use [`coraza-coreruleset/crs/v4`](../../crs/v4).
For the Coraza `coraza.conf-recommended` file, use [`coraza-coreruleset/coraza/v3`](../../coraza/v3).

## Include alias

| Path | Description |
|---|---|
| `@owasp_crs_lts/` | OWASP CRS LTS rules directory |
| `@crs-setup-lts.conf.example` | Upstream CRS setup file (renamed from `crs-setup.conf.example`) |
| `@crs-setup-lts.conf.example-nodefaultact` | Same, with `SecDefaultAction` lines commented out, allowing custom ones to be set |

The distinct `@owasp_crs_lts/` alias (vs `@owasp_crs/` for the latest line) lets both bundles live in the same binary, with the choice of which to load deferred to runtime. See `example/runtime-toggle/` in the repo for an end-to-end demo.

> ⚠️ **CRS rule IDs collide between the latest and LTS lines** (e.g. `id:930100` exists in both). Bundle both freely, but `Include` rules from exactly one bundle at runtime, or the Coraza parser will reject duplicates.

## Quick start

```go
import (
    "github.com/corazawaf/coraza/v3"
    lts "github.com/corazawaf/coraza-coreruleset/lts/v4"
    corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
    "github.com/jcchavezs/mergefs"
)

func main() {
    waf, _ := coraza.NewWAF(
        coraza.NewWAFConfig().
            WithDirectives(`
                Include @coraza.conf-recommended
                Include @crs-setup-lts.conf.example
                Include @owasp_crs_lts/REQUEST-911-METHOD-ENFORCEMENT.conf
            `).
            WithRootFS(mergefs.Merge(lts.FS, corazaconf.FS)),
    )
    _ = waf
}
```

## Runtime version

`lts.Version` exposes the bundled upstream CRS LTS tag (e.g. `"v4.25.0"`).

## Tags

Module tags follow upstream CRS LTS patches: `lts/v4.25.0`, `lts/v4.25.1`, …
