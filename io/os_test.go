package io

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOsFilesystem(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		path := "./testdata/test.txt"
		_, err := OSFS.Open(path)
		assert.NoError(t, err)
	})

	t.Run("does not exist", func(t *testing.T) {
		path := "./testdata/doesnotexist.txt"
		_, err := OSFS.Open(path)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, fs.ErrNotExist))
	})
}
