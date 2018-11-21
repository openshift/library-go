package resourceapply

import (
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	storageclientv1 "k8s.io/client-go/kubernetes/typed/storage/v1"

	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

// ApplyStorageClass merges objectmeta, tries to write everything else
func ApplyStorageClass(client storageclientv1.StorageClassesGetter, required *storagev1.StorageClass) (*storagev1.StorageClass, bool, error) {
	existing, err := client.StorageClasses().Get(required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := client.StorageClasses().Create(required)
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	resourcemerge.EnsureObjectMeta(modified, &existing.ObjectMeta, required.ObjectMeta)
	contentSame := equality.Semantic.DeepEqual(existing, required)
	if contentSame && !*modified {
		return existing, false, nil
	}

	// Provisioner, Parameters, ReclaimPolicy, and VolumeBindingMode are immutable
	recreate := resourcemerge.BoolPtr(false)
	resourcemerge.SetStringIfSet(recreate, &existing.Provisioner, required.Provisioner)
	resourcemerge.SetMapStringStringIfSet(recreate, &existing.Parameters, required.Parameters)
	if required.ReclaimPolicy != nil && !equality.Semantic.DeepEqual(existing.ReclaimPolicy, required.ReclaimPolicy) {
		existing.ReclaimPolicy = required.ReclaimPolicy
		*recreate = true
	}
	resourcemerge.SetStringSliceIfSet(modified, &existing.MountOptions, required.MountOptions)
	if required.AllowVolumeExpansion != nil && !equality.Semantic.DeepEqual(existing.AllowVolumeExpansion, required.AllowVolumeExpansion) {
		existing.AllowVolumeExpansion = required.AllowVolumeExpansion
	}
	if required.VolumeBindingMode != nil && !equality.Semantic.DeepEqual(existing.VolumeBindingMode, required.VolumeBindingMode) {
		existing.VolumeBindingMode = required.VolumeBindingMode
		*recreate = true
	}
	if required.AllowedTopologies != nil && !equality.Semantic.DeepEqual(existing.AllowedTopologies, required.AllowedTopologies) {
		existing.AllowedTopologies = required.AllowedTopologies
	}

	if *recreate {
		err := client.StorageClasses().Delete(existing.Name, nil)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, false, err
		}
		actual, err := client.StorageClasses().Create(existing)
		return actual, true, err
	}
	actual, err := client.StorageClasses().Update(existing)
	return actual, true, err
}
