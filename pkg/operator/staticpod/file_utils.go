package staticpod

import (
	"os"
	"path"

	"io/ioutil"
	"k8s.io/klog/v2"
)

func WriteFileAtomic(content []byte, filePerms os.FileMode, resource, contentDir, filename string) error {
	tmpFile, err := writeTemporaryFile(content, filePerms, contentDir, filename)
	if err != nil {
		return err
	}

	klog.Infof("Renaming %s manifest %q to %q ...", resource, tmpFile, path.Join(contentDir, filename))
	return os.Rename(tmpFile, path.Join(contentDir, filename))
}

func writeTemporaryFile(content []byte, filePerms os.FileMode, contentDir, filename string) (string, error) {
	klog.Infof("Creating a temporary file for %q ...", path.Join(contentDir, filename))
	tmpfile, err := ioutil.TempFile(contentDir, filename)
	if err != nil {
		return "", err
	}
	defer tmpfile.Close()
	if err := tmpfile.Chmod(filePerms); err != nil {
		return "", err
	}
	klog.Infof("Writing to the temporary file %q ...", tmpfile)
	if _, err := tmpfile.Write(content); err != nil {
		return "", err
	}
	return tmpfile.Name(), nil
}
