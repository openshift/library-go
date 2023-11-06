package cloudprovider

import (
	"strings"

	 configv1 "github.com/openshift/api/config/v1"
)

// String converts the IBMCloudServiceName into its string equivalent.
func (name configv1.IBMCloudServiceName) String() string {
	switch name {
	case configv1.IBMCloudServiceCIS:
		return "CIS"
	case configv1.IBMCloudServiceCOS:
		return "COS"
	case configv1.IBMCloudServiceDNSServices:
		return "DNSServices"
	case configv1.IBMCloudServiceGlobalSearch:
		return "GlobalSearch"
	case configv1.IBMCloudServiceGlobalTagging:
		return "GlobalTagging"
	case configv1.IBMCloudServiceHyperProtect:
		return "HyperProtect"
	case configv1.IBMCloudServiceIAM:
		return "IAM"
	case configv1.IBMCloudServiceKeyProtect:
		return "KeyProtect"
	case configv1.IBMCloudServiceResourceController:
		return "ResourceController"
	case configv1.IBMCloudServiceResourceManager:
		return "ResourceManager"
	case configv1.IBMCloudServiceVPC:
		return "VPC"
	default:
		return ""
	}
}

func ToIBMCloudServiceName(name string) (configv1.IBMCloudServiceName, error) {
	// Convert to lowercase to prevent any miscasing in the name.
	switch strings.ToLower(name) {
	case "cis":
		return configv1.IBMCloudServiceCIS, nil
	case "cos":
		return configv1.IBMCloudServiceCOS, nil
	case "dnsservices":
		return configv1.IBMCloudServiceDNSServices, nil
	case "globalsearch":
		return configv1.IBMCloudServiceGlobalSearch, nil
	case "globaltagging":
		return configv1.IBMCloudServiceGlobalTagging, nil
	case "hyperprotect":
		return configv1.IBMCloudServiceHyperProtect, nil
	case "iam":
		return configv1.IBMCloudServiceIAM, nil
	case "keyprotect":
		return configv1.IBMCloudServiceKeyProtect, nil
	case "resourcecontroller":
		return configv1.IBMCloudServiceResourceController, nil
	case "resourcemanager":
		return configv1.IBMCloudServiceResourceManager, nil
	case "vpc":
		return configv1.IBMCloudServiceVPC, nil
	default:
		return "", fmt.Errorf("unknown IBM Cloud service name: %s", name)
	}
}
