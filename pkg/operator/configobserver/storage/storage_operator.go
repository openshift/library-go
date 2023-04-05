package storage

import (
	"reflect"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	opv1 "github.com/openshift/api/operator/v1"
	oplistersv1 "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	storageOperatorName = "cluster"
)

type StorageLister interface {
	StorageLister() oplistersv1.StorageLister
}

func NewStorageObserveFunc(configPath []string) configobserver.ObserveConfigFunc {
	return (&observeStorageFlags{
		configPath: configPath,
	}).ObserveStorageOperator
}

type observeStorageFlags struct {
	configPath []string
}

// ObserveStorageOperator observes the storage.operator.openshift.io/cluster object and writes
// its content to an unstructured object in a string map at the path from the constructor
func (f *observeStorageFlags) ObserveStorageOperator(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret, f.configPath)
	}()

	storageLister := genericListers.(StorageLister)

	errs := []error{}
	observedConfig := map[string]interface{}{}
	storageOperator, err := storageLister.StorageLister().Get(storageOperatorName)
	if errors.IsNotFound(err) {
		recorder.Warningf("ObserveStorageOperator", "storage.%s/%s not found", opv1.GroupName, storageOperatorName)
		return observedConfig, errs
	}
	if err != nil {
		return existingConfig, append(errs, err)
	}

	newStorageMap := storageToMap(storageOperator)
	if len(newStorageMap) > 0 {
		if err := unstructured.SetNestedStringMap(observedConfig, newStorageMap, f.configPath...); err != nil {
			return existingConfig, append(errs, err)
		}
	}

	currentStorageMap, _, err := unstructured.NestedStringMap(existingConfig, f.configPath...)
	if err != nil {
		errs = append(errs, err)
		// keep going on read error from existing config
	}

	if !reflect.DeepEqual(currentStorageMap, newStorageMap) {
		recorder.Eventf("ObserveStorageOperator", "storage changed to %q", newStorageMap)
	}

	return observedConfig, errs
}

func storageToMap(storage *opv1.Storage) map[string]string {
	if storage.Spec.VSphereStorageDriver == opv1.CSIWithMigrationDriver {
		return map[string]string{"OPENSHIFT_DO_VSPHERE_MIGRATION": "true"}
	}

	return nil
}
