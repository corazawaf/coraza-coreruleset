package coraza

import "testing"

func TestTrimToAlias(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "bare alias", in: "@coraza.conf-recommended", want: "@coraza.conf-recommended"},
		{name: "no alias", in: "/etc/coraza/custom.conf", want: "/etc/coraza/custom.conf"},
		{name: "root prefix", in: "/@coraza.conf-recommended", want: "@coraza.conf-recommended"},
		{name: "absolute prefix", in: "/usr/src/myrepo/@coraza.conf-recommended", want: "@coraza.conf-recommended"},
		{name: "relative prefix", in: "../@coraza.conf-recommended", want: "@coraza.conf-recommended"},
		{name: "glob pattern", in: "/usr/src/myrepo/@coraza.conf-recommended*", want: "@coraza.conf-recommended*"},
		// Go module cache paths contain `@` mid-segment: not an alias.
		{name: "at sign inside parent dir", in: "/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/@coraza.conf-recommended", want: "@coraza.conf-recommended"},
		{name: "at sign inside parent dir, no alias", in: "/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/custom.conf", want: "/go/pkg/mod/github.com/myorg/myrepo@v1.2.3/custom.conf"},
		{name: "at sign mid file name", in: "/usr/src/myrepo/foo@bar.conf", want: "/usr/src/myrepo/foo@bar.conf"},
		// Anchors on the last alias segment.
		{name: "nested alias segments", in: "/usr/src/@outer/@coraza.conf-recommended", want: "@coraza.conf-recommended"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trimToAlias(tc.in); got != tc.want {
				t.Errorf("trimToAlias(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
