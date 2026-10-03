package crs

import "testing"

func TestTrimToAlias(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "bare alias", in: "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf", want: "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf"},
		{name: "no alias", in: "/etc/coraza/custom.conf", want: "/etc/coraza/custom.conf"},
		{name: "root prefix", in: "/@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf", want: "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf"},
		{name: "absolute prefix", in: "/usr/src/myrepo/@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf", want: "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf"},
		{name: "relative prefix", in: "../@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf", want: "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf"},
		{name: "glob pattern", in: "/usr/src/myrepo/@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf*", want: "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf*"},
		// Go module cache paths contain `@` mid-segment: not an alias.
		{name: "at sign inside parent dir", in: "/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf", want: "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf"},
		{name: "at sign inside parent dir, no alias", in: "/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/custom.conf", want: "/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/custom.conf"},
		{name: "at sign mid file name", in: "/usr/src/myrepo/foo@bar.conf", want: "/usr/src/myrepo/foo@bar.conf"},
		// Anchors on the last alias segment.
		{name: "nested alias segments", in: "/usr/src/@outer/@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf", want: "@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trimToAlias(tc.in); got != tc.want {
				t.Errorf("trimToAlias(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
