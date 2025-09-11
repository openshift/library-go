package staticpod

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func WriteFileAtomic(content []byte, filePerms os.FileMode, fullFilename string) error {
	tmpFile, err := writeTemporaryFile(content, filePerms, fullFilename)
	if err != nil {
		return err
	}

	return os.Rename(tmpFile, fullFilename)
}

func writeTemporaryFile(content []byte, filePerms os.FileMode, fullFilename string) (string, error) {
	contentDir := filepath.Dir(fullFilename)
	filename := filepath.Base(fullFilename)
	tmpfile, err := os.CreateTemp(contentDir, fmt.Sprintf("%s.tmp", filename))
	if err != nil {
		return "", err
	}
	defer tmpfile.Close()
	if err := tmpfile.Chmod(filePerms); err != nil {
		return "", err
	}
	if _, err := tmpfile.Write(content); err != nil {
		return "", err
	}
	return tmpfile.Name(), nil
}

// SwapDirectoriesAtomic can be used to swap two directories atomically.
//
// This function requires absolute paths and will return an error if that's not the case.
func SwapDirectoriesAtomic(dirA, dirB string) error {
	if !filepath.IsAbs(dirA) {
		return fmt.Errorf("not an absolute path: %q", dirA)
	}
	if !filepath.IsAbs(dirB) {
		return fmt.Errorf("not an absolute path: %q", dirB)
	}
	return unix.Renameat2(0, dirA, 0, dirB, unix.RENAME_EXCHANGE)
}
