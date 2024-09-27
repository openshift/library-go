package csidrivercontrollerservicecontroller

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	corev1 "k8s.io/client-go/informers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	opv1 "github.com/openshift/api/operator/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
	dc "github.com/openshift/library-go/pkg/operator/deploymentcontroller"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehash"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	driverImageEnvName        = "DRIVER_IMAGE"
	provisionerImageEnvName   = "PROVISIONER_IMAGE"
	attacherImageEnvName      = "ATTACHER_IMAGE"
	resizerImageEnvName       = "RESIZER_IMAGE"
	snapshotterImageEnvName   = "SNAPSHOTTER_IMAGE"
	livenessProbeImageEnvName = "LIVENESS_PROBE_IMAGE"
	kubeRBACProxyImageEnvName = "KUBE_RBAC_PROXY_IMAGE"
	toolsImageEnvName         = "TOOLS_IMAGE"

	infraConfigName = "cluster"
)

var (
	defaultMinTLSVersion = libgocrypto.TLSVersionToNameOrDie(libgocrypto.DefaultTLSVersion())
)

// WithObservedProxyDeploymentHook creates a deployment hook that injects into the deployment's containers the observed proxy config.
func WithObservedProxyDeploymentHook() dc.DeploymentHookFunc {
	return func(opSpec *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		containerNamesString := deployment.Annotations["config.openshift.io/inject-proxy"]
		err := v1helpers.InjectObservedProxyIntoContainers(
			&deployment.Spec.Template.Spec,
			strings.Split(containerNamesString, ","),
			opSpec.ObservedConfig.Raw,
			csiconfigobservercontroller.ProxyConfigPath()...,
		)
		return err
	}
}

func WithCABundleDeploymentHook(
	configMapNamespace string,
	configMapName string,
	configMapInformer corev1.ConfigMapInformer,
) dc.DeploymentHookFunc {
	return func(_ *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		cm, err := configMapInformer.Lister().ConfigMaps(configMapNamespace).Get(configMapName)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get ConfigMap %s/%s: %v", configMapNamespace, configMapName, err)
		}
		_, ok := cm.Data["ca-bundle.crt"]
		if !ok {
			return nil
		}

		// Inject the CA bundle into the requested containers. This annotation is congruent to the
		// one used by CVO and the proxy hook) to inject proxy information.
		containerNamesString := deployment.Annotations["config.openshift.io/inject-proxy-cabundle"]
		err = v1helpers.InjectTrustedCAIntoContainers(
			&deployment.Spec.Template.Spec,
			configMapName,
			strings.Split(containerNamesString, ","),
		)
		if err != nil {
			return err
		}

		// Now that the CA bundle is inject into the containers, add an annotation to the deployment
		// so that it's rolled out when the ConfigMap content changes.
		inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferenceFromLister(
			configMapInformer.Lister(),
			nil,
			resourcehash.NewObjectRef().ForConfigMap().InNamespace(configMapNamespace).Named(configMapName),
		)
		if err != nil {
			return fmt.Errorf("invalid dependency reference: %w", err)
		}

		return addObjectHash(deployment, inputHashes)
	}
}

// WithConfigMapHashAnnotationHook creates a deployment hook that annotates a Deployment with a config map's hash.
func WithConfigMapHashAnnotationHook(
	namespace string,
	configMapName string,
	configMapInformer corev1.ConfigMapInformer,
) dc.DeploymentHookFunc {
	return func(opSpec *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferenceFromLister(
			configMapInformer.Lister(),
			nil,
			resourcehash.NewObjectRef().ForConfigMap().InNamespace(namespace).Named(configMapName),
		)
		if err != nil {
			return fmt.Errorf("invalid dependency reference: %w", err)
		}
		return addObjectHash(deployment, inputHashes)
	}
}

// WithSecretHashAnnotationHook creates a deployment hook that annotates a Deployment with a secret's hash.
func WithSecretHashAnnotationHook(
	namespace string,
	secretName string,
	secretInformer corev1.SecretInformer,
) dc.DeploymentHookFunc {
	return func(opSpec *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferenceFromLister(
			nil,
			secretInformer.Lister(),
			resourcehash.NewObjectRef().ForSecret().InNamespace(namespace).Named(secretName),
		)
		if err != nil {
			return fmt.Errorf("invalid dependency reference: %w", err)
		}
		return addObjectHash(deployment, inputHashes)
	}
}

// WithReplicasHook sets the deployment.Spec.Replicas field according to the ControlPlaneTopology
// mode. If the topology is set to 'HighlyAvailable' then the number of replicas will be two.
// Else it will be one. When node ports or hostNetwork are used, maxSurge=0 should be set in the
// Deployment RollingUpdate strategy to prevent the new pod from getting stuck
// waiting for a node with free ports.
func WithReplicasHook(configInformer configinformers.SharedInformerFactory) dc.DeploymentHookFunc {
	return func(_ *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		infra, err := configInformer.Config().V1().Infrastructures().Lister().Get(infraConfigName)
		if err != nil {
			return err
		}

		replicas := int32(1)
		if infra.Status.ControlPlaneTopology == configv1.HighlyAvailableTopologyMode {
			replicas = int32(2)
		}
		deployment.Spec.Replicas = &replicas
		return nil
	}
}

// WithPlaceholdersHook is a manifest hook which replaces the variable with appropriate values set
func WithPlaceholdersHook(configInformer configinformers.SharedInformerFactory) dc.ManifestHookFunc {
	return func(spec *opv1.OperatorSpec, manifest []byte) ([]byte, error) {
		pairs := []string{}
		infra, err := configInformer.Config().V1().Infrastructures().Lister().Get(infraConfigName)
		if err != nil {
			return nil, err
		}
		clusterID := infra.Status.InfrastructureName
		// Replace container images by env vars if they are set
		csiDriver := os.Getenv(driverImageEnvName)
		if csiDriver != "" {
			pairs = append(pairs, []string{"${DRIVER_IMAGE}", csiDriver}...)
		}

		provisioner := os.Getenv(provisionerImageEnvName)
		if provisioner != "" {
			pairs = append(pairs, []string{"${PROVISIONER_IMAGE}", provisioner}...)
		}

		attacher := os.Getenv(attacherImageEnvName)
		if attacher != "" {
			pairs = append(pairs, []string{"${ATTACHER_IMAGE}", attacher}...)
		}

		resizer := os.Getenv(resizerImageEnvName)
		if resizer != "" {
			pairs = append(pairs, []string{"${RESIZER_IMAGE}", resizer}...)
		}

		snapshotter := os.Getenv(snapshotterImageEnvName)
		if snapshotter != "" {
			pairs = append(pairs, []string{"${SNAPSHOTTER_IMAGE}", snapshotter}...)
		}

		livenessProbe := os.Getenv(livenessProbeImageEnvName)
		if livenessProbe != "" {
			pairs = append(pairs, []string{"${LIVENESS_PROBE_IMAGE}", livenessProbe}...)
		}

		kubeRBACProxy := os.Getenv(kubeRBACProxyImageEnvName)
		if kubeRBACProxy != "" {
			pairs = append(pairs, []string{"${KUBE_RBAC_PROXY_IMAGE}", kubeRBACProxy}...)
		}

		tools := os.Getenv(toolsImageEnvName)
		if tools != "" {
			pairs = append(pairs, []string{"${TOOLS_IMAGE}", tools}...)
		}

		// Cluster ID
		pairs = append(pairs, []string{"${CLUSTER_ID}", clusterID}...)

		// Log level
		logLevel := loglevel.LogLevelToVerbosity(spec.LogLevel)
		pairs = append(pairs, []string{"${LOG_LEVEL}", strconv.Itoa(logLevel)}...)

		replaced := strings.NewReplacer(pairs...).Replace(string(manifest))
		return []byte(replaced), nil
	}
}

// WithServingInfo is a manifest hook that replaces ${TLS_CIPHER_SUITES} and ${TLS_MIN_VERSION}
// placeholders with the observed configuration.
func WithServingInfo() dc.ManifestHookFunc {
	return func(opSpec *opv1.OperatorSpec, manifest []byte) ([]byte, error) {
		if len(opSpec.ObservedConfig.Raw) == 0 {
			return manifest, nil
		}

		var config map[string]interface{}
		if err := json.Unmarshal(opSpec.ObservedConfig.Raw, &config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal the observedConfig: %w", err)
		}

		cipherSuites, cipherSuitesFound, err := unstructured.NestedStringSlice(config, csiconfigobservercontroller.CipherSuitesPath()...)
		if err != nil {
			return nil, fmt.Errorf("couldn't get the servingInfo.cipherSuites config from observed config: %w", err)
		}
		if !cipherSuitesFound && bytes.Contains(manifest, []byte("${TLS_CIPHER_SUITES}")) {
			return nil, fmt.Errorf("could not find the servingInfo.cipherSuites config from observed config")
		}

		minTLSVersion, minTLSVersionFound, err := unstructured.NestedString(config, csiconfigobservercontroller.MinTLSVersionPath()...)
		if err != nil {
			return nil, fmt.Errorf("couldn't get the servingInfo.minTLSVersion config from observed config: %v", err)
		}
		if !minTLSVersionFound && bytes.Contains(manifest, []byte("${TLS_MIN_VERSION}")) {
			return nil, fmt.Errorf("could not find the servingInfo.minTLSVersion config from observed config")
		}

		pairs := []string{}
		if cipherSuitesFound && len(cipherSuites) > 0 {
			pairs = append(pairs, []string{"${TLS_CIPHER_SUITES}", strings.Join(cipherSuites, ",")}...)

		}

		// It is possible to set a custom profile with no MinTLSVersion.
		// In this case, the observer will return an empty string, and we
		// fall back to the default (the same as when no profile is set).
		if minTLSVersionFound {
			if len(minTLSVersion) == 0 {
				minTLSVersion = defaultMinTLSVersion
			}
			pairs = append(pairs, []string{"${TLS_MIN_VERSION}", minTLSVersion}...)
		}

		replaced := strings.NewReplacer(pairs...).Replace(string(manifest))
		return []byte(replaced), nil
	}
}

// WithControlPlaneTopologyHook modifies the nodeSelector of the deployment
// based on the control plane topology reported in Infrastructure.Status.ControlPlaneTopology.
// If running with an External control plane, the nodeSelector should not include
// master nodes.
func WithControlPlaneTopologyHook(configInformer configinformers.SharedInformerFactory) dc.DeploymentHookFunc {
	return func(_ *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		infra, err := configInformer.Config().V1().Infrastructures().Lister().Get(infraConfigName)
		if err != nil {
			return err
		}
		if infra.Status.ControlPlaneTopology == configv1.ExternalTopologyMode {
			deployment.Spec.Template.Spec.NodeSelector = map[string]string{}
		}
		return nil
	}
}

// WithLeaderElectionReplacerHook modifies ${LEADER_ELECTION_*} parameters in a yaml file with
// OpenShift's recommended values.
func WithLeaderElectionReplacerHook(defaults configv1.LeaderElection) dc.ManifestHookFunc {
	return func(spec *opv1.OperatorSpec, manifest []byte) ([]byte, error) {
		pairs := []string{
			// truncate to int() to avoid long floats ("137.000000s")
			"${LEADER_ELECTION_LEASE_DURATION}", fmt.Sprintf("%ds", int(defaults.LeaseDuration.Seconds())),
			"${LEADER_ELECTION_RENEW_DEADLINE}", fmt.Sprintf("%ds", int(defaults.RenewDeadline.Seconds())),
			"${LEADER_ELECTION_RETRY_PERIOD}", fmt.Sprintf("%ds", int(defaults.RetryPeriod.Seconds())),
		}
		replaced := strings.NewReplacer(pairs...).Replace(string(manifest))
		return []byte(replaced), nil
	}
}

func addObjectHash(deployment *appsv1.Deployment, inputHashes map[string]string) error {
	if deployment == nil {
		return fmt.Errorf("invalid deployment: %v", deployment)
	}
	if deployment.Annotations == nil {
		deployment.Annotations = map[string]string{}
	}
	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	for k, v := range inputHashes {
		annotationKey := fmt.Sprintf("operator.openshift.io/dep-%s", k)
		if len(annotationKey) > 63 {
			hash := sha256.Sum256([]byte(k))
			annotationKey = fmt.Sprintf("operator.openshift.io/dep-%x", hash)
			annotationKey = annotationKey[:63]
		}
		deployment.Annotations[annotationKey] = v
		deployment.Spec.Template.Annotations[annotationKey] = v
	}
	return nil
}
