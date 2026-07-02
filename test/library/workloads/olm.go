package workloads

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"
)

// OperatorGroup represents an OLM OperatorGroup resource configuration
type OperatorGroup struct {
	Name      string
	Namespace string
}

// Subscription represents an OLM Subscription resource configuration
type Subscription struct {
	Name            string
	Namespace       string
	ChannelName     string
	SourceName      string
	SourceNamespace string
	StartingCSV     string
}

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

// CreateOperatorGroup creates an OperatorGroup for an operator
func (og *OperatorGroup) CreateOperatorGroup(ctx context.Context, dynamicClient dynamic.Interface) error {
	klog.Infof("Creating OperatorGroup %s in namespace %s", og.Name, og.Namespace)

	operatorGroup := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "operators.coreos.com/v1",
			"kind":       "OperatorGroup",
			"metadata": map[string]interface{}{
				"name":      og.Name,
				"namespace": og.Namespace,
			},
			"spec": map[string]interface{}{
				"targetNamespaces": []string{og.Namespace},
			},
		},
	}

	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := dynamicClient.Resource(OperatorGroupGVR()).Namespace(og.Namespace).Create(ctx, operatorGroup, metav1.CreateOptions{})
		if err != nil {
			klog.Warningf("Failed to create OperatorGroup, retrying: %v", err)
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return fmt.Errorf("failed to create OperatorGroup %s: %w", og.Name, err)
	}

	klog.Infof("Successfully created OperatorGroup %s", og.Name)
	return nil
}

// DeleteOperatorGroup deletes the OperatorGroup
func (og *OperatorGroup) DeleteOperatorGroup(ctx context.Context, dynamicClient dynamic.Interface) error {
	klog.Infof("Deleting OperatorGroup %s in namespace %s", og.Name, og.Namespace)

	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
		err := dynamicClient.Resource(OperatorGroupGVR()).Namespace(og.Namespace).Delete(ctx, og.Name, metav1.DeleteOptions{})
		if err != nil {
			klog.Warningf("Failed to delete OperatorGroup, retrying: %v", err)
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return fmt.Errorf("failed to delete OperatorGroup %s: %w", og.Name, err)
	}

	klog.Infof("Successfully deleted OperatorGroup %s", og.Name)
	return nil
}

// CreateSubscription creates a Subscription for an operator
func (sub *Subscription) CreateSubscription(ctx context.Context, dynamicClient dynamic.Interface) error {
	klog.Infof("Creating Subscription %s in namespace %s", sub.Name, sub.Namespace)

	subscription := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "operators.coreos.com/v1alpha1",
			"kind":       "Subscription",
			"metadata": map[string]interface{}{
				"name":      sub.Name,
				"namespace": sub.Namespace,
			},
			"spec": map[string]interface{}{
				"channel":             sub.ChannelName,
				"installPlanApproval": "Automatic",
				"name":                sub.Name,
				"source":              sub.SourceName,
				"sourceNamespace":     sub.SourceNamespace,
			},
		},
	}

	// Add startingCSV if provided using k8s unstructured helper
	if sub.StartingCSV != "" {
		if err := unstructured.SetNestedField(subscription.Object, sub.StartingCSV, "spec", "startingCSV"); err != nil {
			return fmt.Errorf("failed to set startingCSV: %w", err)
		}
	}

	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := dynamicClient.Resource(SubscriptionGVR()).Namespace(sub.Namespace).Create(ctx, subscription, metav1.CreateOptions{})
		if err != nil {
			klog.Warningf("Failed to create Subscription, retrying: %v", err)
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return fmt.Errorf("failed to create Subscription %s: %w", sub.Name, err)
	}

	klog.Infof("Successfully created Subscription %s", sub.Name)
	return nil
}

// DeleteSubscription deletes the Subscription
func (sub *Subscription) DeleteSubscription(ctx context.Context, dynamicClient dynamic.Interface) error {
	klog.Infof("Deleting Subscription %s in namespace %s", sub.Name, sub.Namespace)

	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
		err := dynamicClient.Resource(SubscriptionGVR()).Namespace(sub.Namespace).Delete(ctx, sub.Name, metav1.DeleteOptions{})
		if err != nil {
			klog.Warningf("Failed to delete Subscription, retrying: %v", err)
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return fmt.Errorf("failed to delete Subscription %s: %w", sub.Name, err)
	}

	klog.Infof("Successfully deleted Subscription %s", sub.Name)
	return nil
}

// VerifyCatalogSourceExists checks if required catalog source is available
func (sub *Subscription) VerifyCatalogSourceExists(ctx context.Context, dynamicClient dynamic.Interface) error {
	klog.Infof("Checking for required catalog source: %s", sub.SourceName)

	// Try to get the catalog source
	_, err := dynamicClient.Resource(CatalogSourceGVR()).Namespace(sub.SourceNamespace).Get(ctx, sub.SourceName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("catalog source %s not found in %s: %w", sub.SourceName, sub.SourceNamespace, err)
	}

	klog.Infof("Catalog source %s is available", sub.SourceName)
	return nil
}

// GetCSVName gets the CSV name for the operator using label selector
func GetCSVName(ctx context.Context, dynamicClient dynamic.Interface, namespace, labelSelector string) (string, error) {
	csvList, err := dynamicClient.Resource(CSVGVR()).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return "", fmt.Errorf("failed to list CSVs: %w", err)
	}

	if len(csvList.Items) == 0 {
		return "", fmt.Errorf("no CSV found with label selector: %s", labelSelector)
	}

	if len(csvList.Items) > 1 {
		klog.Warningf("Found %d CSVs matching label selector %s, using first one", len(csvList.Items), labelSelector)
		for i, csv := range csvList.Items {
			klog.Infof("  CSV %d: %s", i, csv.GetName())
		}
	}

	csvName := csvList.Items[0].GetName()
	klog.Infof("Using CSV: %s", csvName)
	return csvName, nil
}

// GetCSVRelatedImages gets the relatedImages from a CSV
func GetCSVRelatedImages(ctx context.Context, dynamicClient dynamic.Interface, namespace, csvName string) ([]RelatedImage, error) {
	csvUnstructured, err := dynamicClient.Resource(CSVGVR()).Namespace(namespace).Get(ctx, csvName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get CSV %s: %w", csvName, err)
	}

	// Extract relatedImages from spec using k8s unstructured helper
	relatedImages, found, err := unstructured.NestedSlice(csvUnstructured.Object, "spec", "relatedImages")
	if err != nil {
		return nil, fmt.Errorf("failed to get relatedImages: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("relatedImages not found in CSV spec")
	}

	// Convert to RelatedImage structs using k8s unstructured helpers
	var images []RelatedImage
	for i, item := range relatedImages {
		imgMap, ok := item.(map[string]interface{})
		if !ok {
			klog.Warningf("Skipping relatedImage[%d]: not a map", i)
			continue
		}

		name, found, err := unstructured.NestedString(imgMap, "name")
		if err != nil {
			klog.Warningf("Skipping relatedImage[%d]: error getting name: %v", i, err)
			continue
		}
		if !found {
			klog.Warningf("Skipping relatedImage[%d]: name field not found", i)
			continue
		}

		image, found, err := unstructured.NestedString(imgMap, "image")
		if err != nil {
			klog.Warningf("Skipping relatedImage[%d]: error getting image: %v", i, err)
			continue
		}
		if !found {
			klog.Warningf("Skipping relatedImage[%d] (%s): image field not found", i, name)
			continue
		}

		images = append(images, RelatedImage{
			Name:  name,
			Image: image,
		})
	}

	klog.Infof("Found %d related images in CSV %s", len(images), csvName)
	return images, nil
}

// WaitForCSVSucceeded waits for CSV to reach Succeeded phase
func WaitForCSVSucceeded(ctx context.Context, dynamicClient dynamic.Interface, namespace, csvName string) error {
	klog.Infof("Waiting for CSV %s/%s to succeed", namespace, csvName)

	return wait.PollUntilContextTimeout(ctx, 10*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		csv, err := dynamicClient.Resource(CSVGVR()).Namespace(namespace).Get(ctx, csvName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.Warningf("CSV %s not found yet, retrying", csvName)
				return false, nil
			}
			return false, err
		}

		// Get the phase from status
		phase, found, err := unstructured.NestedString(csv.Object, "status", "phase")
		if err != nil || !found {
			klog.Warningf("CSV %s has no phase yet", csvName)
			return false, nil
		}

		klog.Infof("CSV %s phase: %s", csvName, phase)

		if phase == "Succeeded" {
			klog.Infof("CSV %s succeeded", csvName)
			return true, nil
		}

		if phase == "Failed" {
			return false, fmt.Errorf("CSV %s failed", csvName)
		}

		return false, nil
	})
}

// GetPackageManifest fetches packagemanifest values dynamically for a given package
// Returns a Subscription struct populated with channel, source, and starting CSV information
func GetPackageManifest(ctx context.Context, dynamicClient dynamic.Interface, packageName, namespace string) (*Subscription, error) {
	klog.Infof("Fetching packagemanifest values for %s", packageName)

	// Get the package manifest
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

	klog.Infof("Found package manifest: channel=%s, source=%s, startingCSV=%s", defaultChannel, catalogSource, startingCSV)

	return &Subscription{
		Name:            packageName,
		Namespace:       namespace,
		ChannelName:     defaultChannel,
		SourceName:      catalogSource,
		SourceNamespace: catalogSourceNamespace,
		StartingCSV:     startingCSV,
	}, nil
}
