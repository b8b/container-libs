//go:build freebsd

package xattrs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fakeListOperation builds a listOperation (as listxattr expects) that yields
// the per-namespace attributes in attrs, or fails with the per-namespace error
// in errs, letting us drive listxattr without a real filesystem/jail.
func fakeListOperation(attrs map[int][]string, errs map[int]error) func(namespace int) ([]string,
	error) {
	return func(namespace int) ([]string, error) {
		if err, ok := errs[namespace]; ok {
			return nil, err
		}
		return attrs[namespace], nil
	}
}

// TestListxattrNamespaceErrors covers the #1278 guard in listxattr: listing the
// system namespace in a FreeBSD jail returns EPERM, which must be skipped
// (returning the readable user attributes) while an EPERM on the user
// namespace, or any non-EPERM error, still fails loudly.
func TestListxattrNamespaceErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		attrs   map[int][]string
		errs    map[int]error
		want    []string
		wantErr error
	}{
		{
			name:  "listxattr_skips_system_namespace_EPERM",
			attrs: map[int][]string{unix.EXTATTR_NAMESPACE_USER: {"test"}},
			errs:  map[int]error{unix.EXTATTR_NAMESPACE_SYSTEM: unix.EPERM},
			want:  []string{"user.test"},
		},
		{
			name:    "listxattr_user_namespace_EPERM_fails",
			errs:    map[int]error{unix.EXTATTR_NAMESPACE_USER: unix.EPERM},
			wantErr: unix.EPERM,
		},
		{
			name:    "listxattr_system_namespace_non_EPERM_fails",
			errs:    map[int]error{unix.EXTATTR_NAMESPACE_SYSTEM: unix.EACCES},
			wantErr: unix.EACCES,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := fakeListOperation(tc.attrs, tc.errs)
			got, err := listxattr(op)
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
