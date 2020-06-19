package credentialsrequestcontroller

import (
	"context"
	"crypto/sha256"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/dynamic"

	"github.com/openshift/client-go/config/clientset/versioned/scheme"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
)

const (
	credentialsRequestGroup    = "cloudcredential.openshift.io"
	credentialsRequestVersion  = "v1"
	credentialsRequestResource = "credentialsrequests"

	specHashAnnotation = "operator.openshift.io/spec-hash"
)

var (
	credentialsRequestResourceGVR schema.GroupVersionResource = schema.GroupVersionResource{
		Group:    credentialsRequestGroup,
		Version:  credentialsRequestVersion,
		Resource: credentialsRequestResource,
	}
)

func readCredentialRequestsOrDie(objBytes []byte) *unstructured.Unstructured {
	udi, _, err := scheme.Codecs.UniversalDecoder().Decode(objBytes, nil, &unstructured.Unstructured{})
	if err != nil {
		panic(err)
	}
	return udi.(*unstructured.Unstructured)
}

func applyCredentialsRequest(
	client dynamic.Interface,
	recorder events.Recorder,
	required *unstructured.Unstructured,
	expectedGeneration int64,
) (*unstructured.Unstructured, bool, error) {
	if required.GetName() == "" {
		return nil, false, fmt.Errorf("invalid object: name cannot be empty")
	}

	if err := addCredentialsRequestHash(required); err != nil {
		return nil, false, err
	}

	crClient := client.Resource(credentialsRequestResourceGVR).Namespace(required.GetNamespace())
	existing, err := crClient.Get(context.TODO(), required.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := crClient.Create(context.TODO(), required, metav1.CreateOptions{})
		if err == nil {
			recorder.Eventf(
				fmt.Sprintf("%sCreated", required.GetKind()),
				"Created %s because it was missing",
				resourcehelper.FormatResourceForCLIWithNamespace(required))
			return actual, true, err
		}
		recorder.Warningf(
			fmt.Sprintf("%sCreateFailed", required.GetKind()),
			"Failed to create %s: %v",
			resourcehelper.FormatResourceForCLIWithNamespace(required),
			err)
		return nil, false, err
	}
	if err != nil {
		return nil, false, err
	}

	// Check CredentialRequest.Generation.
	needApply := false
	if existing.GetGeneration() != expectedGeneration {
		needApply = true
	}

	// Check specHashAnnotation
	existingAnnotations := existing.GetAnnotations()
	if existingAnnotations == nil || existingAnnotations[specHashAnnotation] != required.GetAnnotations()[specHashAnnotation] {
		needApply = true
	}

	if !needApply {
		return existing, false, nil
	}

	requiredCopy := required.DeepCopy()
	existing.Object["spec"] = requiredCopy.Object["spec"]
	actual, err := crClient.Update(context.TODO(), existing, metav1.UpdateOptions{})
	if err != nil {
		return nil, false, err
	}
	return actual, existing.GetResourceVersion() != actual.GetResourceVersion(), nil
}

func addCredentialsRequestHash(cr *unstructured.Unstructured) error {
	jsonBytes, err := json.Marshal(cr.Object["spec"])
	if err != nil {
		return err
	}
	specHash := fmt.Sprintf("%x", sha256.Sum256(jsonBytes))
	annotations := cr.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[specHashAnnotation] = specHash
	cr.SetAnnotations(annotations)
	return nil
}
