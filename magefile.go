// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/magefile/mage/sh"
)

// Subpackage destinations. Each downloader writes into one of these and
// regenerates the corresponding runtime `version.go` (except plugins/, whose
// version is hand-maintained).
//
// Regression tests live in their own modules (crs/tests/v4, lts/tests/v4,
// plugins/tests) so importing a bundle doesn't download its test corpus.
const (
	crsRulesDir  = "crs/v4/rules"
	crsTestsDir  = "crs/tests/v4"
	crsAlias     = "@owasp_crs"
	crsSetupFile = "@crs-setup.conf.example"
	crsPkgDir    = "crs/v4"
	crsPkgName   = "crs"

	ltsRulesDir = "lts/v4/rules"
	ltsTestsDir = "lts/tests/v4"
	ltsAlias    = "@owasp_crs_lts"
	// ltsSetupFile is deliberately distinct from crsSetupFile: the upstream file
	// is named crs-setup.conf.example in both lines, so without a rename the two
	// bundles' setups would collide when merged into one root FS (mergefs returns
	// the first match), making the line un-selectable. Renaming completes the
	// coexistence that the @owasp_crs_lts/ rule alias starts.
	ltsSetupFile = "@crs-setup-lts.conf.example"
	ltsPkgDir    = "lts/v4"
	ltsPkgName   = "lts"

	corazaFilesDir = "coraza/v3/files"
	corazaPkgDir   = "coraza/v3"
	corazaPkgName  = "coraza"

	pluginsFilesDir = "plugins/files"
	pluginsTestsDir = "plugins/tests"
	pluginsAlias    = "@owasp_plugins"
	pluginsManifest = "plugins/versions.json"
	// pluginsLicensesDir holds each plugin's upstream LICENSE as
	// licenses/<plugin name>/LICENSE. It sits outside the @owasp_plugins/
	// alias so `Include @owasp_plugins/*` never picks up a license file.
	pluginsLicensesDir = "licenses"
)

// secDefaultActionRe matches uncommented `SecDefaultAction "phase:N,..."` lines,
// optionally indented. Already-commented lines (starting with `#`) are not
// matched.
var secDefaultActionRe = regexp.MustCompile(`^[ \t]*SecDefaultAction\s+"phase:`)

// pluginManifest mirrors the schema of plugins/versions.json.
type pluginManifest struct {
	Plugins []pluginEntry `json:"plugins"`
}

type pluginEntry struct {
	Name    string `json:"name"`
	Repo    string `json:"repo"`
	Version string `json:"version"`
	// Excluded, when non-empty, is the reason the plugin is kept out of the
	// bundle. The entry stays in versions.json so Renovate keeps tracking
	// upstream releases that might make it bundleable again.
	Excluded string `json:"excluded,omitempty"`
}

// =============================================================================
// Mage targets
// =============================================================================

// DownloadAll runs every downloader. Use this from CI / the Renovate update
// workflow to keep all bundles in lockstep.
func DownloadAll() error {
	if err := DownloadCRS(); err != nil {
		return err
	}
	if err := DownloadLTS(); err != nil {
		return err
	}
	if err := DownloadCoraza(); err != nil {
		return err
	}
	return DownloadPlugins()
}

// DownloadCRS downloads the latest OWASP CRS bundle into crs/v4/ and
// regenerates crs/v4/version.go.
func DownloadCRS() error {
	if err := downloadCRSLine(crsVersion, crsRulesDir, crsTestsDir, crsAlias, crsSetupFile); err != nil {
		return err
	}
	if err := writeVersionFile(crsPkgDir, crsPkgName, crsVersion, "OWASP CRS upstream"); err != nil {
		return err
	}
	fmt.Printf("Updated CRS to version %q\n", crsVersion)
	return nil
}

// DownloadLTS downloads the OWASP CRS LTS bundle into lts/v4/ and regenerates
// lts/v4/version.go. The extractor renames `@owasp_crs` → `@owasp_crs_lts` so
// the LTS bundle can coexist with the latest CRS bundle in the same binary.
func DownloadLTS() error {
	if err := downloadCRSLine(ltsVersion, ltsRulesDir, ltsTestsDir, ltsAlias, ltsSetupFile); err != nil {
		return err
	}
	if err := writeVersionFile(ltsPkgDir, ltsPkgName, ltsVersion, "OWASP CRS LTS upstream"); err != nil {
		return err
	}
	fmt.Printf("Updated CRS LTS to version %q\n", ltsVersion)
	return nil
}

// DownloadCoraza downloads the Coraza recommended config into coraza/v3/files/
// and regenerates coraza/v3/version.go.
//
// No `-nodefaultact` variant is produced here: upstream Coraza ships no
// SecDefaultAction in coraza.conf-recommended (all SecDefaultAction defaults
// live in the CRS setup file), so the plain file is already safe to combine
// with user-defined SecDefaultAction directives. A test in coraza/v3 guards
// this assumption against upstream drift.
func DownloadCoraza() error {
	uri := fmt.Sprintf("https://raw.githubusercontent.com/corazawaf/coraza/%s/coraza.conf-recommended", corazaVersion)
	body, err := getDataFromURL(uri)
	if err != nil {
		return err
	}

	if err := cleanupOldRules(corazaFilesDir); err != nil {
		return err
	}
	if err := os.MkdirAll(corazaFilesDir, 0o755); err != nil {
		return err
	}

	dst := filepath.Join(corazaFilesDir, "@coraza.conf-recommended")
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		return err
	}

	if err := writeVersionFile(corazaPkgDir, corazaPkgName, corazaVersion, "Coraza upstream"); err != nil {
		return err
	}
	fmt.Printf("Updated Coraza config to version %q\n", corazaVersion)
	return nil
}

// DownloadPlugins downloads each plugin listed in plugins/versions.json into
// plugins/files/@owasp_plugins/, their licenses into
// plugins/files/licenses/<plugin name>/, and their regression tests into
// plugins/tests/.
// Does not touch plugins/version.go — that's hand-maintained.
func DownloadPlugins() error {
	manifest, err := readPluginManifest(pluginsManifest)
	if err != nil {
		return err
	}
	var plugins []pluginEntry
	for _, p := range manifest.Plugins {
		if p.Excluded != "" {
			fmt.Printf("Skipping excluded CRS plugin %q: %s\n", p.Name, p.Excluded)
			continue
		}
		plugins = append(plugins, p)
	}

	// Fetch every plugin archive before touching the tree, so a failed
	// download can't leave a half-wiped bundle behind.
	readers := make([]*zip.Reader, len(plugins))
	for i, p := range plugins {
		r, err := fetchPluginZip(p)
		if err != nil {
			return fmt.Errorf("plugin %s@%s: %w", p.Name, p.Version, err)
		}
		readers[i] = r
	}

	dstDir := filepath.Join(pluginsFilesDir, pluginsAlias)
	licensesDir := filepath.Join(pluginsFilesDir, pluginsLicensesDir)
	if err := cleanupOldRules(pluginsFilesDir); err != nil {
		return err
	}
	if err := cleanupTestsDir(pluginsTestsDir); err != nil {
		return err
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}

	for i, p := range plugins {
		if err := extractPlugin(p, readers[i], dstDir, licensesDir, pluginsTestsDir); err != nil {
			return fmt.Errorf("plugin %s@%s: %w", p.Name, p.Version, err)
		}
		fmt.Printf("Updated CRS plugin %q to version %q\n", p.Name, p.Version)
	}
	return nil
}

// Test runs `go test ./...` in every workspace submodule. The examples' tests
// double as integration tests: they load the bundles into Coraza and check
// that requests are blocked or allowed as expected.
func Test() error {
	for _, m := range []string{
		"crs/v4", "crs/tests/v4", "coraza/v3", "lts/v4", "lts/tests/v4", "plugins", "plugins/tests",
		"example/latest", "example/lts", "example/combined",
	} {
		fmt.Printf(">>> go test ./... in %s\n", m)
		if err := sh.RunV("go", "test", "-C", m, "./..."); err != nil {
			return fmt.Errorf("%s: %w", m, err)
		}
	}
	return nil
}

// =============================================================================
// Release tagging
// =============================================================================

type releaseSpec struct {
	// expectedMajor: empty means no major-version constraint (plugins).
	expectedMajor string
	// versionPin: empty means no prefix constraint; e.g. "v4.25." locks lts/v4.
	versionPin string
	// testsModule, when set, is the module holding this bundle's regression
	// tests. It is tagged with the same version in the same run, so a bundle
	// and its tests can never be released out of step.
	testsModule string
}

var releasableModules = map[string]releaseSpec{
	"crs/v4":    {expectedMajor: "4", testsModule: "crs/tests/v4"},
	"lts/v4":    {expectedMajor: "4", versionPin: "v4.25.", testsModule: "lts/tests/v4"},
	"coraza/v3": {expectedMajor: "3"},
	"plugins":   {testsModule: "plugins/tests"},
}

var (
	semverRe       = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	versionConstRe = regexp.MustCompile(`(?m)^const Version\s*=\s*"([^"]+)"`)
	majorRe        = regexp.MustCompile(`^v(\d+)`)
	majorSuffixRe  = regexp.MustCompile(`/v\d+$`)
)

// Tag pushes an annotated git tag for `module` at the currently checked-out
// HEAD, plus one for its regression-tests module when it has one (e.g.
// crs/v4 also tags crs/tests/v4). The version is read from <module>/version.go
// — no explicit version argument is needed, so the operator can't typo it.
//
// Usage: go run mage.go tag <module>
//
//	<module> ∈ {crs/v4, lts/v4, coraza/v3, plugins}
//
// The git remote pointing at corazawaf/coraza-coreruleset defaults to
// "origin" (correct in CI); set TAG_REMOTE (e.g. TAG_REMOTE=upstream) when
// tagging from a fork clone.
func Tag(module string) error {
	remote := os.Getenv("TAG_REMOTE")
	if remote == "" {
		remote = "origin"
	}
	spec, ok := releasableModules[module]
	if !ok {
		return fmt.Errorf("unknown module %q; valid: crs/v4, lts/v4, coraza/v3, plugins", module)
	}
	version, err := readBundledVersion(module)
	if err != nil {
		return err
	}
	if err := validateReleaseVersion(module, spec, version); err != nil {
		return err
	}
	tags := []string{moduleTag(module, version)}
	if spec.testsModule != "" {
		tags = append(tags, moduleTag(spec.testsModule, version))
	}
	for _, tag := range tags {
		if err := assertTagAbsent(remote, tag); err != nil {
			return err
		}
	}
	if err := assertHeadOnMain(remote); err != nil {
		return err
	}
	for _, tag := range tags {
		fmt.Printf(">>> tagging %s\n", tag)
		if err := sh.RunV("git", "tag", "-a", tag, "-m", "Release "+tag); err != nil {
			return err
		}
	}
	// One push for all tags, so a bundle is never published without its tests.
	return sh.RunV("git", append([]string{"push", "--atomic", remote}, tags...)...)
}

// moduleTag returns the git tag for `module` at `version`. Per
// https://go.dev/ref/mod#vcs-version, the tag prefix for a module in a
// subdirectory is the subdirectory WITHOUT the major version suffix:
// crs/v4 tags as crs/v4.26.0 (not crs/v4/v4.26.0), crs/tests/v4 as
// crs/tests/v4.26.0, plugins as plugins/v0.1.0. Go tooling would never
// resolve a tag that keeps the /vN directory.
func moduleTag(module, version string) string {
	return majorSuffixRe.ReplaceAllString(module, "") + "/" + version
}

func readBundledVersion(module string) (string, error) {
	path := filepath.Join(module, "version.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	m := versionConstRe.FindStringSubmatch(string(data))
	if m == nil {
		return "", fmt.Errorf("could not find `const Version = \"...\"` in %s", path)
	}
	return m[1], nil
}

func validateReleaseVersion(module string, spec releaseSpec, version string) error {
	if !semverRe.MatchString(version) {
		return fmt.Errorf("%s/version.go has malformed Version %q (expected vX.Y.Z)", module, version)
	}
	if spec.expectedMajor != "" {
		actual := majorRe.FindStringSubmatch(version)[1]
		if actual != spec.expectedMajor {
			return fmt.Errorf("%s requires v%s.x.x (Go semver rule for /v%s import paths); got %s",
				module, spec.expectedMajor, spec.expectedMajor, version)
		}
	}
	if spec.versionPin != "" && !strings.HasPrefix(version, spec.versionPin) {
		return fmt.Errorf("%s only accepts %sx versions; got %s", module, spec.versionPin, version)
	}
	return nil
}

func assertTagAbsent(remote, tag string) error {
	out, err := sh.Output("git", "tag", "--list", tag)
	if err != nil {
		return fmt.Errorf("git tag --list %s: %w", tag, err)
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("tag %s already exists locally", tag)
	}
	out, err = sh.Output("git", "ls-remote", "--tags", remote, tag)
	if err != nil {
		return fmt.Errorf("git ls-remote --tags %s %s: %w", remote, tag, err)
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("tag %s already exists on %s", tag, remote)
	}
	return nil
}

// assertHeadOnMain refuses to tag commits that aren't part of <remote>/main, so a
// module version can never be published from unreviewed code (Go module
// versions are immutable once fetched through the proxy).
func assertHeadOnMain(remote string) error {
	if err := sh.Run("git", "fetch", "--quiet", remote, "main"); err != nil {
		return fmt.Errorf("git fetch %s main: %w", remote, err)
	}
	err := sh.Run("git", "merge-base", "--is-ancestor", "HEAD", "FETCH_HEAD")
	if err == nil {
		return nil
	}
	if sh.ExitStatus(err) == 1 {
		return fmt.Errorf("HEAD is not on %s/main; only commits merged into main can be tagged", remote)
	}
	return fmt.Errorf("git merge-base --is-ancestor HEAD %s/main: %w", remote, err)
}

// =============================================================================
// CRS / LTS shared download path
// =============================================================================

func downloadCRSLine(version, rulesDir, testsDir, alias, setupFile string) error {
	rulesDstDir := filepath.Join(rulesDir, alias)

	// Fetch the archive before touching the tree, so a failed download (rate
	// limit, network) can't leave a wiped bundle behind.
	crsZip, err := getDataFromURL(archiveZipURL("coreruleset/coreruleset", version))
	if err != nil {
		return err
	}

	r, err := zip.NewReader(bytes.NewReader(crsZip), int64(len(crsZip)))
	if err != nil {
		return err
	}
	zipRoot, err := zipTopLevelDir(r)
	if err != nil {
		return err
	}

	// Wipe the whole rules dir, not just the alias subdir: the setup file, its
	// -nodefaultact variant, and LICENSE live at the top level, and a stale copy
	// would keep shipping in the embed if upstream ever renamed or dropped one.
	if err := cleanupOldRules(rulesDir); err != nil {
		return err
	}
	if err := cleanupTestsDir(testsDir); err != nil {
		return err
	}
	if err := os.MkdirAll(rulesDstDir, 0o755); err != nil {
		return err
	}

	rulesPrefix := zipRoot + "rules/"
	testsPrefix := zipRoot + "tests/regression/tests/"

	var setupExamplePath string
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		switch f.Name {
		case zipRoot + "LICENSE":
			if err := copyZipFile(f, filepath.Join(rulesDir, "LICENSE")); err != nil {
				return err
			}
			continue
		case zipRoot + "crs-setup.conf.example":
			setupExamplePath = filepath.Join(rulesDir, setupFile)
			if err := copyZipFile(f, setupExamplePath); err != nil {
				return err
			}
			continue
		}

		if strings.HasPrefix(f.Name, testsPrefix) {
			if !strings.HasSuffix(f.Name, ".yaml") {
				continue
			}
			if err := copyZipTestFile(f, testsDir, strings.TrimPrefix(f.Name, testsPrefix)); err != nil {
				return err
			}
			continue
		}

		if strings.HasPrefix(f.Name, rulesPrefix) {
			filename := strings.TrimPrefix(f.Name, rulesPrefix)
			if strings.HasSuffix(filename, ".example") {
				continue
			}
			fPath, err := zipDest(rulesDstDir, filename)
			if err != nil {
				return err
			}
			if err := extractRuleFile(f, fPath); err != nil {
				return err
			}
		}
	}

	if setupExamplePath != "" {
		if err := writeNodefaultactVariant(setupExamplePath); err != nil {
			return err
		}
	}
	return nil
}

// =============================================================================
// Plugins
// =============================================================================

func fetchPluginZip(p pluginEntry) (*zip.Reader, error) {
	body, err := getDataFromURL(archiveZipURL(p.Repo, p.Version))
	if err != nil {
		return nil, err
	}
	return zip.NewReader(bytes.NewReader(body), int64(len(body)))
}

func extractPlugin(p pluginEntry, r *zip.Reader, rulesDstDir, licensesDstDir, testsDstDir string) error {
	zipRoot, err := zipTopLevelDir(r)
	if err != nil {
		return err
	}
	pluginsPrefix := zipRoot + "plugins/"
	testsPrefix := zipRoot + "tests/regression/"

	licenseFound := false
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		if f.Name == zipRoot+"LICENSE" {
			dst, err := zipDest(licensesDstDir, filepath.Join(p.Name, "LICENSE"))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := copyZipFile(f, dst); err != nil {
				return err
			}
			licenseFound = true
			continue
		}

		if strings.HasPrefix(f.Name, testsPrefix) {
			if !strings.HasSuffix(f.Name, ".yaml") {
				continue
			}
			if err := copyZipTestFile(f, testsDstDir, strings.TrimPrefix(f.Name, testsPrefix)); err != nil {
				return err
			}
			continue
		}

		if strings.HasPrefix(f.Name, pluginsPrefix) {
			filename := strings.TrimPrefix(f.Name, pluginsPrefix)
			fPath, err := zipDest(rulesDstDir, filename)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(fPath), 0o755); err != nil {
				return err
			}
			// Mirrors the CRS handling: -config.conf is the plugin's
			// counterpart of crs-setup.conf.example and is copied verbatim,
			// keeping the commented-out SecActions that document its settings
			// (including how to disable it); rule files are comment-stripped.
			copyFn := extractRuleFile
			if strings.HasSuffix(filename, "-config.conf") {
				copyFn = copyZipFile
			}
			if err := copyFn(f, fPath); err != nil {
				return err
			}
		}
	}
	// The plugins are redistributed under their upstream license, so a
	// release without one must not ship.
	if !licenseFound {
		return fmt.Errorf("no LICENSE at the root of the %s archive", p.Repo)
	}
	return nil
}

func readPluginManifest(path string) (*pluginManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m pluginManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// =============================================================================
// SecDefaultAction-free variants
// =============================================================================

// writeNodefaultactVariant copies src to <src>-nodefaultact, commenting out any
// uncommented `SecDefaultAction "phase:N,..."` lines (so users can set their
// own without Coraza's "redefining SecDefaultAction" error). SplitAfter
// preserves line terminators, so the variant matches the source's
// trailing-newline state byte-for-byte except for the commented lines.
func writeNodefaultactVariant(srcPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.Grow(len(data))
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if secDefaultActionRe.MatchString(line) {
			buf.WriteString("# ")
		}
		buf.WriteString(line)
	}
	return os.WriteFile(srcPath+"-nodefaultact", buf.Bytes(), 0o644)
}

// =============================================================================
// Generated version.go writers
// =============================================================================

// writeVersionFile regenerates <pkgDir>/version.go with a `const Version = ...`
// matching the just-downloaded upstream tag.
func writeVersionFile(pkgDir, pkgName, version, sourceDesc string) error {
	path := filepath.Join(pkgDir, "version.go")
	content := fmt.Sprintf(`// Code generated by mage; DO NOT EDIT.

package %s

// Version is the %s tag this module bundles.
const Version = %q
`, pkgName, sourceDesc, version)
	return os.WriteFile(path, []byte(content), 0o644)
}

// =============================================================================
// HTTP helpers
// =============================================================================

// archiveZipURL returns the source-archive URL for a GitHub repo at a tag.
// Anonymous requests use the plain /archive/ endpoint. With GITHUB_TOKEN set,
// we switch to the REST API zipball endpoint: github.com's web download
// endpoints (archive, codeload, raw) reject any request carrying an
// `Authorization: Bearer` header with a 403, while api.github.com requires it.
func archiveZipURL(repo, tag string) string {
	if os.Getenv("GITHUB_TOKEN") != "" {
		return fmt.Sprintf("https://api.github.com/repos/%s/zipball/%s", repo, tag)
	}
	return fmt.Sprintf("https://github.com/%s/archive/%s.zip", repo, tag)
}

// zipTopLevelDir returns the single top-level directory (e.g. "repo-1.2.3/")
// GitHub source archives wrap their content in. It must be read from the
// archive rather than reconstructed from the tag: the /archive/ endpoint names
// it <repo>-<version>/ while the API zipball uses <owner>-<repo>-<shortsha>/.
func zipTopLevelDir(r *zip.Reader) (string, error) {
	if len(r.File) == 0 {
		return "", fmt.Errorf("empty zip archive")
	}
	name := r.File[0].Name
	idx := strings.Index(name, "/")
	if idx == -1 {
		return "", fmt.Errorf("unexpected zip layout: entry %q not under a root directory", name)
	}
	return name[:idx+1], nil
}

// httpClient strips the Authorization header on cross-host redirects.
// The API zipball endpoint redirects to codeload.github.com, which rejects the
// `Authorization: Bearer <token>` header with a 403, so we keep auth only on
// the original host.
var httpClient = &http.Client{
	// Bounds the whole request, including reading the archive body, so a
	// stalled download fails CI instead of hanging it.
	Timeout: 5 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			req.Header.Del("Authorization")
		}
		return nil
	},
}

func getDataFromURL(uri string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	// Attach the token only for api.github.com: GitHub's web download hosts
	// 403 any Bearer-authenticated request (see archiveZipURL).
	if token := os.Getenv("GITHUB_TOKEN"); token != "" && strings.HasPrefix(uri, "https://api.github.com/") {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected status %d", uri, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// =============================================================================
// Zip / file helpers
// =============================================================================

// extractRuleFile copies a zip entry to dst, preserving the file's leading
// comment block — the run of `#`-prefixed lines terminated by the first blank
// or non-comment line — verbatim, and stripping comment / blank lines from
// the rest of the file. For .conf files (CRS and plugins) the leading block is
// the license header; detecting it instead of hardcoding its length keeps the
// full license text intact if upstream ever reformats it. CRS .data files
// carry no license header — for them this preserves whatever short leading
// commentary upstream ships (generator notes, section labels), which is
// equally safe: Coraza ignores `#` lines in data files.
func extractRuleFile(f *zip.File, dst string) (err error) {
	source, err := f.Open()
	if err != nil {
		return err
	}
	defer source.Close()

	target, err := os.Create(dst)
	if err != nil {
		return err
	}
	// A partially written rule file must not be left behind for the embed.
	defer func() {
		if cerr := target.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
		}
	}()

	scanner := bufio.NewScanner(source)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// bufio.Writer errors are sticky: any failed write surfaces at Flush.
	w := bufio.NewWriter(target)
	inHeader := true
	for scanner.Scan() {
		line := scanner.Bytes()
		if inHeader {
			if len(line) > 0 && line[0] == '#' {
				w.Write(line)
				w.WriteByte('\n')
				continue
			}
			inHeader = false
		}
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 || text[0] == '#' {
			continue
		}
		w.Write(line)
		w.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return w.Flush()
}

// copyZipFile copies a zip entry verbatim to dst.
func copyZipFile(f *zip.File, dst string) error {
	source, err := f.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	data, err := io.ReadAll(source)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// copyZipTestFile copies a regression-test zip entry verbatim to
// <testsDir>/<rel>, creating its parent directories.
func copyZipTestFile(f *zip.File, testsDir, rel string) error {
	dst, err := zipDest(testsDir, rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return copyZipFile(f, dst)
}

// zipDest joins a path taken from a zip entry onto dir, refusing any path
// that would escape dir (zip slip): absolute paths, `..` segments, and the
// like. Upstream archives are trusted, but the plugin list keeps growing.
func zipDest(dir, rel string) (string, error) {
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("refusing zip entry %q: escapes %s", rel, dir)
	}
	return filepath.Join(dir, rel), nil
}

// =============================================================================
// Cleanup
// =============================================================================

// cleanupOldRules removes the directory entirely. Called on the whole
// generated dir (not just the rules subdir) so files upstream renames or
// drops can't linger across downloads.
func cleanupOldRules(dir string) error {
	return os.RemoveAll(dir)
}

// testsModuleFiles are the top-level files of a tests module that belong to
// the module itself rather than to the downloaded regression-test corpus.
var testsModuleFiles = map[string]bool{
	"go.mod":        true,
	"go.sum":        true,
	"tests.go":      true,
	"tests_test.go": true,
}

// cleanupTestsDir wipes the contents of a tests module directory but
// preserves the module's own files (see testsModuleFiles).
func cleanupTestsDir(testsDir string) error {
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(testsDir, 0o755)
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && testsModuleFiles[name] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(testsDir, name)); err != nil {
			return err
		}
	}
	return nil
}
