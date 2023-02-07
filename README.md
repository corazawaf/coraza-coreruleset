# Coraza Coreruleset

## Usage

In order to use CRS, you need to load the coreruleset FileSystem:

```go
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
func main() {
    // ...
    waf, err := coraza.NewWAF(
        coraza.NewWAFConfig().
        WithDirectives(`
            Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
            Include my/local/rule.conf
        `).
        WithRootFS(merged_fs.NewMergedFS(coreruleset.FS, coraza.OSFS{})),
    )
    // ...
}
```
