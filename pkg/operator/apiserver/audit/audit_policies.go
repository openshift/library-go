package audit

import (
	"errors"
	"strings"

	assets "github.com/openshift/library-go/pkg/operator/apiserver/audit/bindata"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
)

const (
	// AuditPoliciesConfigMapFileName hold the name of the file that you need to pass to WithAuditPolicies to get the audit policy config map
	AuditPoliciesConfigMapFileName = "audit-policies-cm.yaml"
)

// WithAuditPolicies is meant to wrap a standard Asset function usually provided by an operator.
// It delegates to GetAuditPolicies when the filename matches the predicate for retrieving a audit policy config map for target namespace.
func WithAuditPolicies(targetNamespace string, assetDelegateFunc resourceapply.AssetFunc) resourceapply.AssetFunc {
	return func(file string) ([]byte, error) {
		if file == AuditPoliciesConfigMapFileName {
			return getAuditPolicies(targetNamespace)
		}
		return assetDelegateFunc(file)
	}
}

// GetAuditPolicies returns a raw config map that holds the audit policies for the target namespaces
func getAuditPolicies(targetNamespace string) ([]byte, error) {
	if len(targetNamespace) == 0 {
		return nil, errors.New("please specify the target namespace")
	}
	auditPoliciesTemplate, err := assets.Asset("pkg/operator/apiserver/audit/manifests/audit-policies-cm.yaml")
	if err != nil {
		return nil, err
	}

	r := strings.NewReplacer(
		"${TARGET_NAMESPACE}", targetNamespace,
	)
	auditPoliciesForTargetNs := []byte(r.Replace(string(auditPoliciesTemplate)))

	// we don't care about the output, just make sure that after replacing the ns it will serialize
	resourceread.ReadConfigMapV1OrDie(auditPoliciesForTargetNs)
	return auditPoliciesForTargetNs, nil
}
