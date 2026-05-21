package encryptionstatus

import (
	"strings"
)

// KEKByKeyID groups observed kekIds per plugin keyId across health reports.
// Only healthy reports with non-empty keyId and kekId are included.
func KEKByKeyID(reports []KMSPluginHealthReport) map[string][]string {
	result := map[string][]string{}
	for _, report := range reports {
		if !isHealthyReport(report) {
			continue
		}
		result[report.KeyID] = append(result[report.KeyID], report.KEKID)
	}
	return result
}

// ConvergedKEKForKeyID returns the unanimous kekId for keyID when every healthy report for that keyId agrees.
func ConvergedKEKForKeyID(reports []KMSPluginHealthReport, keyID string) (kekID string, ok bool) {
	if keyID == "" {
		return "", false
	}

	byKeyID := KEKByKeyID(reports)
	kekIDs, found := byKeyID[keyID]
	if !found || len(kekIDs) == 0 {
		return "", false
	}

	uniq := map[string]struct{}{}
	for _, id := range kekIDs {
		if id == "" {
			return "", false
		}
		uniq[id] = struct{}{}
	}
	if len(uniq) != 1 {
		return "", false
	}
	for id := range uniq {
		return id, true
	}
	return "", false
}

func isHealthyReport(report KMSPluginHealthReport) bool {
	return strings.EqualFold(report.Status, "healthy")
}
