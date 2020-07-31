package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"

	assets "github.com/openshift/library-go/pkg/operator/apiserver/audit/bindata"
	libgoapiserver "github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
)

const (
	// AuditPoliciesConfigMapFileName hold the name of the file that you need to pass to WithAuditPolicies to get the audit policy config map
	AuditPoliciesConfigMapFileName = "audit-policies-cm.yaml"

	auditPolicyAsset = "pkg/operator/apiserver/audit/manifests/audit-policies-cm.yaml"
)

// WithAuditPolicies is meant to wrap a standard Asset function usually provided by an operator.
// It delegates to GetAuditPolicies when the filename matches the predicate for retrieving a audit policy config map for target namespace and name.
func WithAuditPolicies(targetName string, targetNamespace string, assetDelegateFunc resourceapply.AssetFunc) resourceapply.AssetFunc {
	return func(file string) ([]byte, error) {
		if file == AuditPoliciesConfigMapFileName {
			return getRawAuditPolicies(targetName, targetNamespace)
		}
		return assetDelegateFunc(file)
	}
}

// GetAuditPolicies returns a config map that holds the audit policies for the target namespaces and name
func GetAuditPolicies(targetName, targetNamespace string) (*corev1.ConfigMap, error) {
	rawAuditPolicies, err := getRawAuditPolicies(targetName, targetNamespace)
	if err != nil {
		return nil, err
	}

	return resourceread.ReadConfigMapV1OrDie(rawAuditPolicies), nil
}

// getRawAuditPolicies returns a raw config map that holds the audit policies for the target namespaces and name
func getRawAuditPolicies(targetName, targetNamespace string) ([]byte, error) {
	if len(targetNamespace) == 0 {
		return nil, errors.New("please specify the target namespace")
	}
	if len(targetName) == 0 {
		return nil, errors.New("please specify the target name")
	}
	auditPoliciesTemplate, err := assets.Asset(auditPolicyAsset)
	if err != nil {
		return nil, err
	}

	r := strings.NewReplacer(
		"${TARGET_NAME}", targetName,
		"${TARGET_NAMESPACE}", targetNamespace,
	)
	auditPoliciesForTargetNs := []byte(r.Replace(string(auditPoliciesTemplate)))

	// we don't care about the output, just make sure that after replacing the ns it will serialize
	resourceread.ReadConfigMapV1OrDie(auditPoliciesForTargetNs)
	return auditPoliciesForTargetNs, nil
}

// NewAuditPolicyPathGetter returns a path getter for audit policy file mounted into the given path of a Pod as a directory.
//
// openshift-apiserver and oauth-apiserver mounts the audit policy ConfigMap into
// the above path inside the Pod.
func NewAuditPolicyPathGetter(path string) (libgoapiserver.AuditPolicyPathGetterFunc, error) {
	return newAuditPolicyPathGetter(path)
}

func newAuditPolicyPathGetter(path string) (libgoapiserver.AuditPolicyPathGetterFunc, error) {
	policies, err := readPolicyNamesFromAsset()
	if err != nil {
		return nil, err
	}

	return func(profile string) (string, error) {
		// we expect the keys for audit profile in bindata to be in lower case and
		// have a '.yaml' suffix.
		key := fmt.Sprintf("%s.yaml", strings.ToLower(profile))
		_, exists := policies[key]
		if !exists {
			return "", fmt.Errorf("invalid audit profile - key=%s", key)
		}

		return fmt.Sprintf("%s/%s", path, key), nil
	}, nil
}

func readPolicyNamesFromAsset() (map[string]struct{}, error) {
	bytes, err := assets.Asset(auditPolicyAsset)
	if err != nil {
		return nil, fmt.Errorf("failed to load asset asset=%s - %s", auditPolicyAsset, err)
	}

	rawJSON, err := kyaml.ToJSON(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert asset yaml to JSON asset=%s - %s", auditPolicyAsset, err)
	}

	cm := corev1.ConfigMap{}
	if err := json.Unmarshal(rawJSON, &cm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit policy asset=%s - %s", auditPolicyAsset, err)
	}

	policies := map[string]struct{}{}
	for key := range cm.Data {
		policies[key] = struct{}{}
	}

	return policies, nil
}
