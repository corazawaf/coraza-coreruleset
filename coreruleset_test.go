package coreruleset

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRules(t *testing.T) {
	_, err := FS.Open("@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf")
	require.NoError(t, err)
}
