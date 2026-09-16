package olm

import (
	"context"
	"fmt"
	"time"

	semver "github.com/blang/semver/v4"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
)

// RelatedImage represents an image referenced in a CSV
type RelatedImage struct {
	Name  string
	Image string
}

// OperatorGroupGVR returns the GroupVersionResource for OperatorGroup
func OperatorGroupGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "operators.coreos.com",
		Version:  "v1",
		Resource: "operatorgroups",
	}
}

// SubscriptionGVR returns the GroupVersionResource for Subscription
func SubscriptionGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "operators.coreos.com",
		Version:  "v1alpha1",
		Resource: "subscriptions",
	}
}

// CSVGVR returns the GroupVersionResource for ClusterServiceVersion
func CSVGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "operators.coreos.com",
		Version:  "v1alpha1",
		Resource: "clusterserviceversions",
	}
}

// PackageManifestGVR returns the GroupVersionResource for PackageManifest
func PackageManifestGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "packages.operators.coreos.com",
		Version:  "v1",
		Resource: "packagemanifests",
	}
}

// CatalogSourceGVR returns the GroupVersionResource for CatalogSource
func CatalogSourceGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "operators.coreos.com",
		Version:  "v1alpha1",
		Resource: "catalogsources",
	}
}

// CreateOperatorGroup creates an OperatorGroup for an operator.
//
// This helper accepts unstructured objects to avoid vendoring operator-framework/api
// types in library-go. Callers in individual operator repositories should:
// 1. Vendor the operator-framework/api types they need
// 2. Construct typed OLM objects (e.g., operatorsv1.OperatorGroup)
// 3. Convert to unstructured using runtime.DefaultUnstructuredConverter.ToUnstructured
// 4. Pass the unstructured object to this helper
//
// Example:
//
//	og := &operatorsv1.OperatorGroup{
//	    ObjectMeta: metav1.ObjectMeta{Name: "my-og", Namespace: "my-ns"},
//	    Spec: operatorsv1.OperatorGroupSpec{TargetNamespaces: []string{"my-ns"}},
//	}
//	unstructuredOG, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(og)
//	err := CreateOperatorGroup(ctx, client, &unstructured.Unstructured{Object: unstructuredOG})
func CreateOperatorGroup(ctx context.Context, dynamicClient dynamic.Interface, og *unstructured.Unstructured) error {
	_, err := dynamicClient.Resource(OperatorGroupGVR()).Namespace(og.GetNamespace()).Create(ctx, og, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create OperatorGroup %s: %w", og.GetName(), err)
	}
	return nil
}

// DeleteOperatorGroup deletes the OperatorGroup and waits for it to be fully removed.
// See CreateOperatorGroup for details on using unstructured objects.
func DeleteOperatorGroup(ctx context.Context, dynamicClient dynamic.Interface, og *unstructured.Unstructured) error {
	err := dynamicClient.Resource(OperatorGroupGVR()).Namespace(og.GetNamespace()).Delete(ctx, og.GetName(), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete OperatorGroup %s: %w", og.GetName(), err)
	}

	// Wait for the OperatorGroup to be fully deleted
	return wait.PollUntilContextCancel(ctx, 1*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := dynamicClient.Resource(OperatorGroupGVR()).Namespace(og.GetNamespace()).Get(ctx, og.GetName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	})
}

// CreateSubscription creates a Subscription for an operator.
// See CreateOperatorGroup for details on using unstructured objects.
func CreateSubscription(ctx context.Context, dynamicClient dynamic.Interface, sub *unstructured.Unstructured) error {
	_, err := dynamicClient.Resource(SubscriptionGVR()).Namespace(sub.GetNamespace()).Create(ctx, sub, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Subscription %s: %w", sub.GetName(), err)
	}
	return nil
}

// DeleteSubscription deletes the Subscription and waits for it to be fully removed.
// See CreateOperatorGroup for details on using unstructured objects.
func DeleteSubscription(ctx context.Context, dynamicClient dynamic.Interface, sub *unstructured.Unstructured) error {
	err := dynamicClient.Resource(SubscriptionGVR()).Namespace(sub.GetNamespace()).Delete(ctx, sub.GetName(), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete Subscription %s: %w", sub.GetName(), err)
	}

	// Wait for the Subscription to be fully deleted
	return wait.PollUntilContextCancel(ctx, 1*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := dynamicClient.Resource(SubscriptionGVR()).Namespace(sub.GetNamespace()).Get(ctx, sub.GetName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	})
}

// CatalogSourceExists checks if required catalog source is available.
// The catalogSource and catalogSourceNamespace parameters should come from
// the Subscription's spec.catalogSource and spec.catalogSourceNamespace fields.
func CatalogSourceExists(ctx context.Context, dynamicClient dynamic.Interface, catalogSource, catalogSourceNamespace string) error {
	_, err := dynamicClient.Resource(CatalogSourceGVR()).Namespace(catalogSourceNamespace).Get(ctx, catalogSource, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("catalog source %s not found in %s: %w", catalogSource, catalogSourceNamespace, err)
	}

	return nil
}

// GetTheLatestCSVName gets the CSV name for the operator using label selector.
// When multiple CSVs are found, it returns the one with the highest semver version.
func GetTheLatestCSVName(ctx context.Context, dynamicClient dynamic.Interface, namespace, labelSelector string) (string, error) {
	csvList, err := dynamicClient.Resource(CSVGVR()).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return "", fmt.Errorf("failed to list CSVs: %w", err)
	}

	if len(csvList.Items) == 0 {
		return "", fmt.Errorf("no CSV found with label selector: %s", labelSelector)
	}

	// If only one CSV, return it directly
	if len(csvList.Items) == 1 {
		return csvList.Items[0].GetName(), nil
	}

	// Multiple CSVs found - select the one with the highest semver version
	var latestCSV *unstructured.Unstructured
	var latestVersion semver.Version

	for i := range csvList.Items {
		csv := &csvList.Items[i]
		versionStr, found, err := unstructured.NestedString(csv.Object, "spec", "version")
		if err != nil || !found || versionStr == "" {
			// Skip CSVs without a valid version field
			continue
		}

		version, err := semver.Parse(versionStr)
		if err != nil {
			// Skip CSVs with invalid semver format
			continue
		}

		if latestCSV == nil || version.GT(latestVersion) {
			latestVersion = version
			latestCSV = csv
		}
	}

	if latestCSV == nil {
		// Fallback to first CSV if none have valid versions
		return csvList.Items[0].GetName(), nil
	}

	return latestCSV.GetName(), nil
}

// GetCSVRelatedImages gets the relatedImages from a CSV.
// See CreateOperatorGroup for details on using unstructured objects.
func GetCSVRelatedImages(csv *unstructured.Unstructured) ([]RelatedImage, error) {
	// Extract relatedImages from spec using k8s unstructured helper
	relatedImages, found, err := unstructured.NestedSlice(csv.Object, "spec", "relatedImages")
	if err != nil {
		return nil, fmt.Errorf("failed to get relatedImages: %w", err)
	}
	if !found {
		// Empty relatedImages is valid - return empty slice
		return []RelatedImage{}, nil
	}

	// Convert to RelatedImage structs using k8s unstructured helpers
	var images []RelatedImage
	for _, item := range relatedImages {
		imgMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Skip entries where name field is missing, has wrong type (err != nil),
		// doesn't exist (!found), or is empty
		name, found, err := unstructured.NestedString(imgMap, "name")
		if err != nil || !found || name == "" {
			continue
		}

		// Skip entries where image field is missing, has wrong type (err != nil),
		// doesn't exist (!found), or is empty
		image, found, err := unstructured.NestedString(imgMap, "image")
		if err != nil || !found || image == "" {
			continue
		}

		images = append(images, RelatedImage{
			Name:  name,
			Image: image,
		})
	}

	return images, nil
}

// BuildSubscriptionFromPackageManifest fetches a packagemanifest for a given package
// and builds an unstructured Subscription object populated with the default channel, catalog source, and starting CSV information.
// See CreateOperatorGroup for details on using unstructured objects.
//
// The returned unstructured Subscription can be converted to a typed object in the caller:
//
//	sub := &operatorsv1alpha1.Subscription{}
//	runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredSub.Object, sub)
func BuildSubscriptionFromPackageManifest(ctx context.Context, dynamicClient dynamic.Interface, packageName, namespace string) (*unstructured.Unstructured, error) {
	if packageName == "" {
		return nil, fmt.Errorf("packageName cannot be empty")
	}
	if namespace == "" {
		return nil, fmt.Errorf("namespace cannot be empty")
	}

	pm, err := dynamicClient.Resource(PackageManifestGVR()).Namespace(namespace).Get(ctx, packageName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get packagemanifest %s: %w", packageName, err)
	}

	// Extract catalog source name
	catalogSource, found, err := unstructured.NestedString(pm.Object, "status", "catalogSource")
	if err != nil {
		return nil, fmt.Errorf("error reading catalogSource: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("catalogSource not found in packagemanifest")
	}

	// Extract catalog source namespace
	catalogSourceNamespace, found, err := unstructured.NestedString(pm.Object, "status", "catalogSourceNamespace")
	if err != nil {
		return nil, fmt.Errorf("error reading catalogSourceNamespace: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("catalogSourceNamespace not found in packagemanifest")
	}

	// Extract default channel
	defaultChannel, found, err := unstructured.NestedString(pm.Object, "status", "defaultChannel")
	if err != nil {
		return nil, fmt.Errorf("error reading defaultChannel: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("defaultChannel not found in packagemanifest")
	}

	// Extract channels to find the latest CSV
	channels, found, err := unstructured.NestedSlice(pm.Object, "status", "channels")
	if err != nil || !found {
		return nil, fmt.Errorf("could not find channels in packagemanifest")
	}

	var startingCSV string
	for _, ch := range channels {
		channel, ok := ch.(map[string]interface{})
		if !ok {
			continue
		}
		name, found, err := unstructured.NestedString(channel, "name")
		if err != nil || !found {
			continue
		}
		if name == defaultChannel {
			startingCSV, found, err = unstructured.NestedString(channel, "currentCSV")
			if err != nil {
				return nil, fmt.Errorf("error reading currentCSV from channel %s: %w", name, err)
			}
			if !found {
				return nil, fmt.Errorf("currentCSV not found in default channel %s", name)
			}
			break
		}
	}

	if startingCSV == "" {
		return nil, fmt.Errorf("default channel %s not found in packagemanifest channels", defaultChannel)
	}

	subscription := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "operators.coreos.com/v1alpha1",
			"kind":       "Subscription",
			"metadata": map[string]interface{}{
				"name":      packageName,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"channel":             defaultChannel,
				"name":                packageName,
				"source":              catalogSource,
				"sourceNamespace":     catalogSourceNamespace,
				"startingCSV":         startingCSV,
				"installPlanApproval": "Automatic",
			},
		},
	}

	return subscription, nil
}
