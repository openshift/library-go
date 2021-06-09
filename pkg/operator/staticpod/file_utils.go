package staticpod

import (
	"fmt"
	"os"
	"path"

	"io/ioutil"
)

func WriteFileAtomic(content []byte, filePerms os.FileMode, contentDir, filename string) error {
	tmpFile, err := writeTemporaryFile(content, filePerms, contentDir, filename)
	if err != nil {
		return err
	}

	return os.Rename(tmpFile, path.Join(contentDir, filename))
}

func writeTemporaryFile(content []byte, filePerms os.FileMode, contentDir, filename string) (string, error) {
	tmpfile, err := ioutil.TempFile(contentDir, fmt.Sprintf("%s.tmp", filename))
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
