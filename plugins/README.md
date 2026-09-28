# coraza-coreruleset/plugins

Embeds official [OWASP CRS plugins](https://github.com/coreruleset/plugin-registry) so they can be consumed by a Coraza WAF via `WithRootFS`.

This bundle is intentionally **decoupled from any CRS version** — merge it with whichever CRS bundle ([`crs/v4`](../crs/v4) or [`lts/v4`](../lts/v4)) fits the use case.

## Include alias

| Path | Description |
|---|---|
| `@owasp_plugins/` | OWASP CRS plugins directory |

## Bundled plugins

See [`versions.json`](./versions.json) for the full list of bundled plugins and their pinned upstream versions. Renovate keeps each entry up-to-date independently.

Entries carrying an `"excluded"` field are tracked but **not** bundled; the field states why. Currently excluded:

- **google-oauth2** — upstream v1.0.0 fails to parse (rule 9505120 is missing a closing quote), so `coraza.NewWAF` errors on `Include`.
- **fake-bot** — relies on `@inspectFile fake-bot.lua`, which Coraza executes from the OS filesystem and cannot run as Lua, so the rule silently never matches.

To re-enable a plugin, remove its `"excluded"` field and run `go run mage.go downloadPlugins`.

## Quick start

```go
import (
    "github.com/corazawaf/coraza/v3"
    crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
    corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
    "github.com/corazawaf/coraza-coreruleset/plugins"
    "github.com/jcchavezs/mergefs"
)

func main() {
    waf, _ := coraza.NewWAF(
        coraza.NewWAFConfig().
            WithDirectives(`
                Include @coraza.conf-recommended
                Include @crs-setup.conf.example
                Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
                Include @owasp_plugins/wordpress-rule-exclusions-before.conf
            `).
            WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS, plugins.FS)),
    )
    _ = waf
}
```

## Runtime version

`plugins.Version` exposes this module's release tag (e.g. `"v0.1.0"`). Individual plugin upstream versions live in [`versions.json`](./versions.json) but are not exposed at runtime.

## Tags

This module's tags are independent semver: `plugins/v0.1.0`, `plugins/v0.2.0`, … starting at `v0.1.0` while the bundle's API and plugin set are still settling.
