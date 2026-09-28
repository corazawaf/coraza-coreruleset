# Coraza Coreruleset

This repo provides Go modules packaged for easy consumption by Go applications that use Coraza.
The following modules are available, each of which embeds a different set of files:
- [OWASP CRS](https://github.com/coreruleset/coreruleset).
- [OWASP CRS LTS line](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/).
- [OWASP CRS official plugins](https://github.com/coreruleset/plugin-registry).
- [Coraza](https://github.com/corazawaf/coraza) recommended configuration file.

## Modules

This is a **multi-module** repo. Each module has its own release cadence, allowing them to be pinned independently and only the needed bundles to be embedded. Every module exposes its embedded files as an `fs.FS` (`FS`) and a `Version` constant. [`mergefs`](https://github.com/jcchavezs/mergefs) utility is a convenient way to merge multiple bundles into a single root FS for Coraza. See [Usage](#usage) for how to combine them.

| Module | Import path | Include aliases it provides | Tag pattern |
|---|---|---|---|
| **Latest CRS** | `github.com/corazawaf/coraza-coreruleset/crs/v4` | `@owasp_crs/`<br>`@crs-setup.conf.example`<br>`@crs-setup.conf.example-nodefaultact` | `crs/v4.26.0`, `crs/v4.26.1`, ... |
| **CRS LTS** | `github.com/corazawaf/coraza-coreruleset/lts/v4` | `@owasp_crs_lts/`<br>`@crs-setup-lts.conf.example`<br>`@crs-setup-lts.conf.example-nodefaultact` | `lts/v4.25.0`, `lts/v4.25.1`, ... |
| **Coraza config** | `github.com/corazawaf/coraza-coreruleset/coraza/v3` | `@coraza.conf-recommended` | `coraza/v3.5.0`, `coraza/v3.6.0`, ... |
| **Official CRS plugins** | `github.com/corazawaf/coraza-coreruleset/plugins` | `@owasp_plugins/` | `plugins/v0.1.0`, `plugins/v0.2.0`, ... |

Note that:
- `@owasp_crs/…`, `@owasp_crs_lts/…`, and `@owasp_plugins/…` are directory aliases. Via `Include` it is possible to include individual files under them, e.g. `@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf`.
- The LTS bundle uses distinct aliases — `@owasp_crs_lts/` for rules and `@crs-setup-lts.conf.example` for setup (rather than `@owasp_crs/` and `@crs-setup.conf.example`). This allows it to coexist with the latest CRS bundle in the same binary and either line to be picked at runtime. Their rule *IDs* still overlap, so within a single `coraza.NewWAF` call `Include` rules from only one line, to avoid seclang parsing errors due to duplicate rule IDs.
- The `-nodefaultact` aliases are copies of the CRS setup files with every `SecDefaultAction "phase:..."` line commented out. Coraza forbids redefining `SecDefaultAction`, so these allow setting custom ones without rewriting the upstream file (e.g. `Include @crs-setup.conf.example-nodefaultact` followed by custom `SecDefaultAction` directives).
- The `Version` constant lets applications introspect what they bundled:

## Usage

Every bundle follows the same pattern: merge the needed modules' `FS` into a single root FS with `mergefs.Merge` and pass it to `WithRootFS`, then `Include` the aliases listed in the [Modules table](#modules). Each bundle claims disjoint paths, so merge order doesn't matter.

- **Latest CRS** — merge `crs.FS` and `corazaconf.FS`, then include `@coraza.conf-recommended`, `@crs-setup.conf.example` and the needed `@owasp_crs/…` rules. See [`example/latest/`](./example/latest/).
- **LTS** — same as above, with `lts/v4` in place of `crs/v4` and the `@owasp_crs_lts/…` / `@crs-setup-lts.conf.example` aliases. See [`example/lts/`](./example/lts/), which also adds an official plugin.
- **Plugins** — additionally merge `plugins.FS` and include the plugin `.conf`s under `@owasp_plugins/`. Bundled plugins and their pinned upstream versions are tracked in [`plugins/versions.json`](./plugins/versions.json); a few are tracked but excluded, see [`plugins/README.md`](./plugins/README.md#bundled-plugins) for which and why.
- **Both CRS lines in one binary** — see [`example/runtime-toggle/`](./example/runtime-toggle/), which switches line via a `--lts` flag.

The `coraza/v3` module's package name is `coraza`, which collides with `github.com/corazawaf/coraza/v3`; import it under an alias, conventionally `corazaconf`.

## Migrating from the legacy `coraza-coreruleset/v4` module

Prior versions of this repo published everything under a single `github.com/corazawaf/coraza-coreruleset/v4` module exposing `coreruleset.FS`. That module is **frozen at `v4.25.0`**.
Migrate to the subpackage modules:

```diff
- import coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
+ import (
+     crs        "github.com/corazawaf/coraza-coreruleset/crs/v4"
+     corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
+     "github.com/jcchavezs/mergefs"
+ )
- WithRootFS(coreruleset.FS)
+ WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS))
```

The `@coraza.conf-recommended` file no longer ships in the same FS as the CRS rules. It has been moved to its own `coraza/v3` module with its own release cadence. This allows to pin Coraza's recommended config independently of the CRS version.

## Updating bundles to newer upstream versions

### Automated (the normal path)

Each upstream release flows in via:

1. **Renovate** watches the version constants in [`versions.go`](./versions.go) (`crsVersion`, `ltsVersion`, `corazaVersion`) and every entry in [`plugins/versions.json`](./plugins/versions.json). When a new upstream tag appears it opens a PR bumping that one constant.
2. The [`updates.yaml`](./.github/workflows/updates.yaml) workflow fires on the Renovate PR, runs `go run mage.go downloadAll`, and pushes the regenerated bundles + `version.go` files + `-nodefaultact` variants back into the same PR branch.

**Maintainer action:** review and merge the PR. After merge, cut the module's release tag via the [`release.yaml`](./.github/workflows/release.yaml) workflow (see [Cutting a release](#cutting-a-release) below).

### Cutting a release

Each releasable module (`crs/v4`, `lts/v4`, `coraza/v3`, `plugins`) is tagged via the [`release.yaml`](./.github/workflows/release.yaml) workflow, triggered from GitHub's **Actions → Release module → Run workflow** specifying the module and optionally a commit SHA.

- **module**: which module to tag (dropdown).
- **ref** *(optional)*: the commit SHA to tag; it must be on `main`. Leave empty to tag the tip of `main`. Useful to tag an earlier commit once `main` has moved on, e.g. when releasing several intermediate upstream versions merged one after another.
- There is no version input, the version is extracted from `<module>/version.go`. Always merge the Renovate / version-bump PR first to bring `version.go` in sync, then dispatch this. The workflow pushes the annotated tag (e.g. `crs/v4.26.1`, as per [Go's tagging convention](https://go.dev/ref/mod#vcs-version)).

The same target also works locally: `go run mage.go tag crs/v4` from a developer machine validates and pushes the tag using the developer's own git identity. It uses the `origin` remote by default; from a fork clone, set `TAG_REMOTE` to the remote pointing at `corazawaf/coraza-coreruleset` (e.g. `TAG_REMOTE=upstream go run mage.go tag crs/v4`).

> **No repo-only patch releases for `crs/v4`, `lts/v4`, `coraza/v3`.** Their version mirrors the upstream tag they bundle, and an existing tag can't be re-cut. A fix to this repo's own code (e.g. `wrapfs.go`) therefore ships with the next upstream version bump. `plugins` has its own semver and can be released at any time.

### Manual fallback

Use this when bumping a version outside of Renovate, or when `updates.yaml` couldn't push to the PR (for example, the GitHub App token expired):

1. Edit [`versions.go`](./versions.go) — bump `crsVersion`, `ltsVersion`, or `corazaVersion`. For plugins, edit [`plugins/versions.json`](./plugins/versions.json).
2. Run `go run mage.go downloadAll`. This re-fetches each upstream archive, materialises the embedded content, regenerates the `version.go` files in each subpackage, and writes the `-nodefaultact` variants.
3. Commit the resulting changes.
