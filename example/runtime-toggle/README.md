# example/runtime-toggle

Bundles **both** the latest OWASP CRS (`crs/v4`) and the LTS CRS (`lts/v4`) into the same Go binary and lets the operator pick which one to load at runtime via a `--lts` flag.

## Why?

CRS LTS is stabilised on the `v4.25.x` line with quarterly bug-fix patches through Q3 2027. CRS latest continues to receive new detections and refactors. Some deployments want both available — for staged rollouts, fleet heterogeneity, or A/B comparison — without shipping two binaries.

## Run it

```bash
go run .          # uses crs/v4 (latest)
go run . --lts    # same binary, uses lts/v4
```

## How it works

The two bundles expose distinct seclang `Include` aliases:

| Bundle | Alias |
|---|---|
| `crs/v4` | `@owasp_crs/` |
| `lts/v4` | `@owasp_crs_lts/` |

That alone is what lets both embedded bundles coexist in one binary. The runtime switch picks one `fs.FS` (via `mergefs.Merge`) and uses the matching alias in the `Include` directives.

> ⚠️ CRS rule IDs collide between the two lines (`id:930100` exists in both `@owasp_crs/REQUEST-930-…` and `@owasp_crs_lts/REQUEST-930-…`). A single Coraza WAF must `Include` rules from exactly one bundle at a time, or the seclang parser will reject the duplicates. This example follows that pattern — only one bundle's rules are included per `coraza.NewWAF` call.

## Binary-size trade-off

Bundling both bundles in a single binary adds roughly **~750 KB** versus picking one at build time (CRS rules are ~750 KB embedded). For most server deployments this is negligible; for resource-constrained edge/embedded use cases, prefer the single-bundle pattern shown in [`../latest/`](../latest/) or [`../lts/`](../lts/).
