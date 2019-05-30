package hold

import (
	"path/filepath"
)

var (
	installerHoldFile = "INSTALLER_HOLD"
)

func InstallerFile(podManifestDir string) string {
	return filepath.Join(podManifestDir, installerHoldFile)
}
