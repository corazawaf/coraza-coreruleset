# Coraza Coreruleset

## Usage

```go
func main() {
 // First we initialize our waf and our seclang parser
 waf, err := coraza.NewWAF(
  coraza.NewWAFConfig().
   WithDirectives("Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf").
   WithRootFS(coreruleset.FS),
 )
```
