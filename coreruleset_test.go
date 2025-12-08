package coreruleset

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRules(t *testing.T) {
	f, err := FS.Open("@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf")
	require.NoError(t, err)
	f.Close()

	f, err = PluginsFS.Open("@owasp_plugins/wordpress-rule-exclusions-before.conf")
	require.NoError(t, err)
	f.Close()

	_, err = FS.(subFS).ReadFile("/usr/src/github.com/myorg/myrepo/@crs-setup.conf.example")
	require.NoError(t, err)
}
