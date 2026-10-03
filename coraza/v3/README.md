# coraza-coreruleset/coraza/v3

Embeds the [Coraza](https://github.com/corazawaf/coraza) recommended configuration file (`coraza.conf-recommended`) so it can be consumed by a Coraza WAF via `WithRootFS`.

Pair this filesystem with a CRS bundle ([`crs/v4`](../../crs/v4) or [`lts/v4`](../../lts/v4)) using `mergefs.Merge`.

## Include aliases

| Path | Description |
|---|---|
| `@coraza.conf-recommended` | Upstream Coraza recommended base configuration |

Unlike the CRS setup files in [`crs/v4`](../../crs/v4) and [`lts/v4`](../../lts/v4), this file needs no `-nodefaultact` variant: upstream Coraza ships no `SecDefaultAction` in it (those defaults live exclusively in the CRS setup file), so it is always safe to combine with custom `SecDefaultAction` directives.

## Quick start

```go
import (
    "github.com/corazawaf/coraza/v3"
    crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
    corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
    "github.com/jcchavezs/mergefs"
)

func main() {
    waf, _ := coraza.NewWAF(
        coraza.NewWAFConfig().
            WithDirectives(`
                Include @coraza.conf-recommended
                SecRuleEngine On
                Include @crs-setup.conf.example
                Include @owasp_crs/*.conf
            `).
            WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)),
    )
    _ = waf
}
```

The package name is `coraza`, which collides with `github.com/corazawaf/coraza/v3`. Alias the import when using both:

```go
import corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
```

## Runtime version

`coraza.Version` (or `corazaconf.Version` with the alias) exposes the bundled upstream Coraza tag (e.g. `"v3.5.0"`).

## Tags

Module tags follow upstream Coraza releases: `coraza/v3.5.0`, `coraza/v3.6.0`, …
