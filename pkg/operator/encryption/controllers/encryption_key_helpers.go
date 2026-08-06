package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/crypto"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

type encryptionKeyPlan struct {
	needed         bool
	keyID          uint64
	reasons        []string
	internalReason string
}

func planNextEncryptionKey(
	desiredEncryptionState map[schema.GroupResource]state.GroupResourceState,
	currentMode state.Mode,
	externalReason string,
	encryptedGRs []schema.GroupResource,
	desiredProviderCfg kmsProviderConfig,
) (*encryptionKeyPlan, error) {
	plan := &encryptionKeyPlan{}
	reasons := []string{}

	var (
		commonReason        string
		hasCommonReason     bool
		commonReasonDiffers bool
	)

	for gr, grKeys := range desiredEncryptionState {
		latestKeyID, internalReason, needed, err := needsNewKey(grKeys, currentMode, externalReason, encryptedGRs, desiredProviderCfg)
		if err != nil {
			return nil, err
		}
		if !needed {
			continue
		}

		if !hasCommonReason {
			commonReason = internalReason
			hasCommonReason = true
		} else if commonReason != internalReason {
			commonReasonDiffers = true
		}

		plan.needed = true
		nextKeyID := latestKeyID + 1
		if plan.keyID < nextKeyID {
			plan.keyID = nextKeyID
		}
		reasons = append(reasons, fmt.Sprintf("%s-%s", gr.Resource, internalReason))
	}

	if !plan.needed {
		return plan, nil
	}
	if hasCommonReason && !commonReasonDiffers && len(reasons) > 1 {
		reasons = []string{commonReason}
	}

	sort.Strings(reasons)
	plan.reasons = reasons
	plan.internalReason = strings.Join(reasons, ", ")
	return plan, nil
}

// encryptionKeyBuildResult is the in-memory key material plus any referenced
// Secret/ConfigMap fetched while building it. Callers that also need to hash
// the KMS config (key controller) reuse the refs to avoid a second API round-trip.
type encryptionKeyBuildResult struct {
	keyState  state.KeyState
	refSecret *corev1.Secret
	refCM     *corev1.ConfigMap
}

func buildEncryptionKeyState(
	ctx context.Context,
	keyID uint64,
	currentMode state.Mode,
	apiServerEncryption configv1.APIServerEncryption,
	desiredProviderCfg kmsProviderConfig,
	secretClient corev1client.SecretsGetter,
	configMapClient corev1client.ConfigMapsGetter,
	internalReason string,
	externalReason string,
	kmsEndpointOverride string,
) (*encryptionKeyBuildResult, error) {
	bs := crypto.ModeToNewKeyFunc[currentMode]()
	result := &encryptionKeyBuildResult{
		keyState: state.KeyState{
			Key: apiserverv1.Key{
				Name:   fmt.Sprintf("%d", keyID),
				Secret: base64.StdEncoding.EncodeToString(bs),
			},
			Mode:           currentMode,
			InternalReason: internalReason,
			ExternalReason: externalReason,
		},
	}

	if currentMode != state.KMS {
		return result, nil
	}

	endpoint := kmsEndpointOverride
	if len(endpoint) == 0 {
		endpoint = fmt.Sprintf(kmsEndpointFormat, keyID)
	}
	result.keyState.KMS = &state.KMSState{
		Encryption: &apiserverv1.KMSConfiguration{
			APIVersion: "v2",
			Name:       fmt.Sprintf("%d", keyID),
			Endpoint:   endpoint,
			Timeout:    &metav1.Duration{Duration: defaultKMSTimeout},
		},
		Plugin: apiServerEncryption.KMS,
	}

	if secretName, expectedKeys, err := desiredProviderCfg.referencedSecretName(); err != nil {
		return nil, err
	} else if len(secretName) > 0 {
		refSecret, err := secretClient.Secrets(openshiftConfigNS).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get secret %s in %s: %w", secretName, openshiftConfigNS, err)
		}
		result.refSecret = refSecret
		for _, key := range expectedKeys {
			v, ok := refSecret.Data[key]
			if !ok {
				return nil, fmt.Errorf("secret %s in %s is missing required key %q", secretName, openshiftConfigNS, key)
			}
			if err := result.keyState.KMS.PluginSecretData.Set(secretName, key, v); err != nil {
				return nil, err
			}
		}
	}

	if cmName, expectedKeys, err := desiredProviderCfg.referencedConfigMapName(); err != nil {
		return nil, err
	} else if len(cmName) > 0 {
		refCM, err := configMapClient.ConfigMaps(openshiftConfigNS).Get(ctx, cmName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get configmap %s in %s: %w", cmName, openshiftConfigNS, err)
		}
		result.refCM = refCM
		for _, key := range expectedKeys {
			v, ok := refCM.Data[key]
			if !ok {
				return nil, fmt.Errorf("configmap %s in %s is missing required key %q", cmName, openshiftConfigNS, key)
			}
			if err := result.keyState.KMS.PluginConfigMapData.Set(cmName, key, []byte(v)); err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

func buildEncryptionKeySecret(
	ctx context.Context,
	instanceName string,
	keyID uint64,
	currentMode state.Mode,
	apiServerEncryption configv1.APIServerEncryption,
	desiredProviderCfg kmsProviderConfig,
	secretClient corev1client.SecretsGetter,
	configMapClient corev1client.ConfigMapsGetter,
	internalReason string,
	externalReason string,
	kmsEndpointOverride string,
) (*corev1.Secret, error) {
	result, err := buildEncryptionKeyState(
		ctx,
		keyID,
		currentMode,
		apiServerEncryption,
		desiredProviderCfg,
		secretClient,
		configMapClient,
		internalReason,
		externalReason,
		kmsEndpointOverride,
	)
	if err != nil {
		return nil, err
	}
	return secrets.FromKeyState(instanceName, result.keyState)
}
