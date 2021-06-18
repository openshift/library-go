package audit

import (
	"bytes"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	assets "github.com/openshift/library-go/pkg/operator/apiserver/audit/bindata"
	libgoapiserver "github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"sigs.k8s.io/yaml"
)

var (
	basePolicy   auditv1.Policy
	profileRules = map[configv1.AuditProfileType][]auditv1.PolicyRule{}

	auditScheme         = runtime.NewScheme()
	auditCodecs         = serializer.NewCodecFactory(auditScheme)
	auditYamlSerializer = json.NewYAMLSerializer(json.DefaultMetaFactory, auditScheme, auditScheme)

	coreScheme         = runtime.NewScheme()
	coreCodecs         = serializer.NewCodecFactory(coreScheme)
	coreYamlSerializer = json.NewYAMLSerializer(json.DefaultMetaFactory, coreScheme, coreScheme)
)

func init() {
	if err := auditv1.AddToScheme(auditScheme); err != nil {
		panic(err)
	}
	if err := corev1.AddToScheme(coreScheme); err != nil {
		panic(err)
	}

	bs, err := assets.Asset("pkg/operator/apiserver/audit/manifests/base-policy.yaml")
	if err != nil {
		panic(err)
	}
	if err := runtime.DecodeInto(coreCodecs.UniversalDecoder(auditv1.SchemeGroupVersion), bs, &basePolicy); err != nil {
		panic(err)
	}

	for _, profile := range []configv1.AuditProfileType{configv1.AuditProfileDefaultType, configv1.WriteRequestBodiesAuditProfileType, configv1.AllRequestBodiesAuditProfileType} {
		manifestName := fmt.Sprintf("%s-rules.yaml", strings.ToLower(string(profile)))
		bs, err := assets.Asset(path.Join("pkg/operator/apiserver/audit/manifests", manifestName))
		if err != nil {
			panic(err)
		}
		var rules []auditv1.PolicyRule
		if err := yaml.Unmarshal(bs, &rules); err != nil {
			panic(err)
		}
		profileRules[profile] = rules
	}
}

// DefaultPolicy brings back the default.yaml audit policy to init the api
func DefaultPolicy() ([]byte, error) {
	policy, err := GetAuditPolicy(configv1.Audit{Profile: configv1.AuditProfileDefaultType})
	if err != nil {
		return nil, fmt.Errorf("failed to retreive default audit policy: %v", err)
	}

	policy.Kind = "Policy"
	policy.APIVersion = auditv1.SchemeGroupVersion.String()

	var buf bytes.Buffer
	if err := auditYamlSerializer.Encode(policy, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WithAuditPolicies is meant to wrap a standard Asset function usually provided by an operator.
// It delegates to GetAuditPolicies when the filename matches the predicate for retrieving a audit policy config map for target namespace and name.
func WithAuditPolicies(targetName string, targetNamespace string, assetDelegateFunc resourceapply.AssetFunc) resourceapply.AssetFunc {
	return func(file string) ([]byte, error) {
		if file != "audit-policies-cm.yaml" {
			return assetDelegateFunc(file)
		}

		cm, err := GetAuditPolicies(targetName, targetNamespace)
		if err != nil {
			return nil, err
		}
		cm.Kind = "ConfigMap"
		cm.APIVersion = "v1"

		var buf bytes.Buffer
		if err := coreYamlSerializer.Encode(cm, &buf); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
}

// GetAuditPolicy computes the audit policy for the given audit config.
// Note: the returned Policy has Kind and APIVersion not set. This is responsibility of the caller
//       when serializing it.
func GetAuditPolicy(audit configv1.Audit) (*auditv1.Policy, error) {
	p := basePolicy.DeepCopy()
	p.Name = string(audit.Profile)

	extraRules, ok := profileRules[audit.Profile]
	if !ok {
		return nil, fmt.Errorf("unknown audit profile %q", audit.Profile)
	}
	p.Rules = append(p.Rules, extraRules...)

	return p, nil
}

// GetAuditPolicies returns a config map that holds the audit policies for the target namespaces and name.
// Note: the returned ConfigMap has Kind and APIVersion not set. This is responsibility of the caller
//       when serializing it.
func GetAuditPolicies(targetName, targetNamespace string) (*corev1.ConfigMap, error) {
	cm := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: targetNamespace,
			Name:      targetName,
		},
		Data: map[string]string{},
	}

	for _, profile := range []configv1.AuditProfileType{configv1.AuditProfileDefaultType, configv1.WriteRequestBodiesAuditProfileType, configv1.AllRequestBodiesAuditProfileType} {
		policy, err := GetAuditPolicy(configv1.Audit{Profile: profile})
		if err != nil {
			return nil, err
		}

		policy.Kind = "Policy"
		policy.APIVersion = auditv1.SchemeGroupVersion.String()

		var buf bytes.Buffer
		if err := auditYamlSerializer.Encode(policy, &buf); err != nil {
			return nil, err
		}

		cm.Data[fmt.Sprintf("%s.yaml", strings.ToLower(string(profile)))] = buf.String()
	}

	return &cm, nil
}

// NewAuditPolicyPathGetter returns a path getter for audit policy file mounted into the given path of a Pod as a directory.
//
// openshift-apiserver and oauth-apiserver mounts the audit policy ConfigMap into
// the above path inside the Pod.
func NewAuditPolicyPathGetter(path string) (libgoapiserver.AuditPolicyPathGetterFunc, error) {
	return func(profile string) (string, error) {
		manifestName := fmt.Sprintf("pkg/operator/apiserver/audit/manifests/%s-rules.yaml", strings.ToLower(profile))
		if _, err := assets.Asset(manifestName); err != nil {
			return "", fmt.Errorf("invalid audit profile %q", profile)
		}

		return filepath.Join(path, fmt.Sprintf("%s.yaml", strings.ToLower(profile))), nil
	}, nil
}
