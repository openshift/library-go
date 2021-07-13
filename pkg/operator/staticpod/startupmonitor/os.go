package startupmonitor

import (
	"io/fs"
	"io/ioutil"
	"os"
)

// ioInterface collects file system level operations that need to be mocked out during tests
type ioInterface interface {
	Symlink(oldname string, newname string) error
	Stat(path string) (os.FileInfo, error)
	Remove(path string) error
	ReadFile(filename string) ([]byte, error)
	ReadDir(dirname string) ([]fs.FileInfo, error)
	WriteFile(filename string, data []byte, perm fs.FileMode) error
}

// realFS is used to dispatch the real system level operations.
type realFS struct{}

// Symlink will call os.Symlink to create a symbolic link.
func (realFS) Symlink(oldname string, newname string) error {
	return os.Symlink(oldname, newname)
}

// Stat will call os.Stat to get the FileInfo for a given path
func (realFS) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// Remove will call os.Remove to remove the path.
func (realFS) Remove(path string) error {
	return os.Remove(path)
}

// ReadFile will call ioutil.ReadFile to read data
func (realFS) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// ReadDir will call ioutil.ReadDir to get a list of fs.FileInfo for the given directory
func (realFS) ReadDir(dirname string) ([]fs.FileInfo, error) {
	return ioutil.ReadDir(dirname)
}

// WriteFile will call ioutil.WriteFile to write data
func (realFS) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	return ioutil.WriteFile(filename, data, perm)
}
