package resourcesynccontroller

import (
	"crypto/x509"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/cert"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation"
)

func CombineCABundleConfigMaps(destinationConfigMap *corev1.ConfigMap, lister corev1listers.ConfigMapLister, additionalAnnotations certrotation.AdditionalAnnotations, inputConfigMaps ...ResourceLocation) (*corev1.ConfigMap, bool, error) {

	var cm *corev1.ConfigMap
	if destinationConfigMap == nil {
		cm = &corev1.ConfigMap{}
	} else {
		cm = destinationConfigMap.DeepCopy()
	}
	certificates := []*x509.Certificate{}
	for _, input := range inputConfigMaps {
		inputConfigMap, err := lister.ConfigMaps(input.Namespace).Get(input.Name)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, false, err
		}

		// configmaps must conform to this
		inputContent := inputConfigMap.Data["ca-bundle.crt"]
		if len(inputContent) == 0 {
			continue
		}
		inputCerts, err := cert.ParseCertsPEM([]byte(inputContent))
		if err != nil {
			return nil, false, fmt.Errorf("configmap/%s in %q is malformed: %v", input.Name, input.Namespace, err)
		}
		certificates = append(certificates, inputCerts...)
	}

	certificates = crypto.FilterExpiredCerts(certificates...)
	finalCertificates := []*x509.Certificate{}
	// now check for duplicates. n^2, but super simple
	for i := range certificates {
		found := false
		for j := range finalCertificates {
			if reflect.DeepEqual(certificates[i].Raw, finalCertificates[j].Raw) {
				found = true
				break
			}
		}
		if !found {
			finalCertificates = append(finalCertificates, certificates[i])
		}
	}

	caBytes, err := crypto.EncodeCertificates(finalCertificates...)
	if err != nil {
		return nil, false, err
	}

	modified := additionalAnnotations.EnsureTLSMetadataUpdate(&cm.ObjectMeta)
	cm.Data = map[string]string{
		"ca-bundle.crt": string(caBytes),
	}
	return cm, modified, nil
}
