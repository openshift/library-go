package certrotation

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ensureOwnerRefAndTLSAnnotations(meta *metav1.ObjectMeta, owner *metav1.OwnerReference, additionalAnnotations AdditionalAnnotations) []string {
	updateReasons := []string{}
	// no ownerReference set
	if owner != nil && ensureOwnerReference(meta, owner) {
		updateReasons = append(updateReasons, fmt.Sprintf("owner reference updated to %#v", owner))
	}
	// ownership annotations not set
	if additionalAnnotations.EnsureTLSMetadataUpdate(meta) {
		updateReasons = append(updateReasons, fmt.Sprintf("annotations set to %#v", additionalAnnotations))
	}
	return updateReasons
}

func ensureSecretTLSTypeSet(secret *corev1.Secret) string {
	// Existing secret not found - no need to update metadata (will be done by needNewSigningCertKeyPair / NeedNewTargetCertKeyPair)
	if len(secret.ResourceVersion) == 0 {
		return ""
	}

	// convert outdated secret type (created by pre 4.7 installer)
	if secret.Type != corev1.SecretTypeTLS {
		secret.Type = corev1.SecretTypeTLS
		// wipe secret contents if tls.crt and tls.key are missing
		_, certExists := secret.Data[corev1.TLSCertKey]
		_, keyExists := secret.Data[corev1.TLSPrivateKeyKey]
		if !certExists || !keyExists {
			secret.Data = map[string][]byte{}
		}
		return fmt.Sprintf("changed type to %s", string(corev1.SecretTypeTLS))
	}
	return ""

}
