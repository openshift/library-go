//go:build linux
// +build linux

package certgraphanalysis

import (
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/opencontainers/selinux/go-selinux"

	"github.com/openshift/library-go/pkg/certs/cert-inspection/certgraphapi"
)

func getOnDiskLocationMetadata(path string) *certgraphapi.OnDiskLocationWithMetadata {
	ret := &certgraphapi.OnDiskLocationWithMetadata{
		OnDiskLocation: certgraphapi.OnDiskLocation{
			Path: path,
		},
	}

	// Get permissions and uid/gid (omit if error occured)
	if info, err := os.Stat(path); err == nil {
		ret.Permissions = info.Mode().Perm().String()
		if statt, ok := info.Sys().(*syscall.Stat_t); ok {
			if u, err := user.LookupId(strconv.FormatUint(uint64(statt.Uid), 10)); err == nil {
				ret.User = u.Name
			}
			if g, err := user.LookupGroupId(strconv.FormatUint(uint64(statt.Gid), 10)); err == nil {
				ret.Group = g.Name
			}
		}
	}

	// Get selinux label (omit if error occured)
	if label, err := selinux.FileLabel(path); err == nil {
		ret.SELinuxOptions = label
	}

	return ret
}
