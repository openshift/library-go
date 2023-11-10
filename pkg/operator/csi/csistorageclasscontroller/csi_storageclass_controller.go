package csistorageclasscontroller

import (
	"context"
	"fmt"
	"time"

	operatorapi "github.com/openshift/api/operator/v1"
	opinformers "github.com/openshift/client-go/operator/informers/externalversions"
	oplisters "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/storage/v1"
	"k8s.io/klog/v2"
)

const (
	defaultScAnnotationKey = "storageclass.kubernetes.io/is-default-class"
)

// StorageClassHookFunc is a hook function to modify a StorageClass.
type StorageClassHookFunc func(*operatorapi.OperatorSpec, *storagev1.StorageClass) error

// This Controller deploys a StorageClass provided by CSI driver operator
// and decides if this StorageClass should be applied as default - if requested.
// If operator wants to request it's StorageClass to be created as default,
// the asset file provided to this controller must have defaultScAnnotationKey set to "true".
// Based on the current StorageClasses in the cluster the controller can decide not
// to deploy given StorageClass as default if there already is any existing default.
// When the controller detects there already is a StorageClass with a same name it
// just copies the default StorageClass annotation from the existing one to prevent
// overwriting value that user might have manually changed.
// If the asset file does not have defaultScAnnotationKey set at all, controller
// just skips any checks and modifications and applies the StorageClass as it is.
// It produces following Conditions:
// StorageClassControllerDegraded - failed to apply StorageClass provided
type CSIStorageClassController struct {
	name               string
	assetFunc          resourceapply.AssetFunc
	files              []string
	kubeClient         kubernetes.Interface
	storageClassLister v1.StorageClassLister
	operatorClient     v1helpers.OperatorClient
	eventRecorder      events.Recorder
	scStateEvaluator   *StorageClassStateEvaluator
	// Optional hook functions to modify the StorageClass.
	// If one of these functions returns an error, the sync
	// fails indicating the ordinal position of the failed function.
	// Also, in that scenario the Degraded status is set to True.
	optionalStorageClassHooks []StorageClassHookFunc
}

func NewCSIStorageClassController(
	name string,
	assetFunc resourceapply.AssetFunc,
	files []string,
	kubeClient kubernetes.Interface,
	informerFactory informers.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient,
	operatorInformer opinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
	optionalStorageClassHooks ...StorageClassHookFunc) factory.Controller {
	clusterCSIDriverLister := operatorInformer.Operator().V1().ClusterCSIDrivers().Lister()
	evaluator := NewStorageClassStateEvaluator(
		kubeClient,
		clusterCSIDriverLister,
		eventRecorder,
	)
	c := &CSIStorageClassController{
		name:                      name,
		assetFunc:                 assetFunc,
		files:                     files,
		kubeClient:                kubeClient,
		storageClassLister:        informerFactory.Storage().V1().StorageClasses().Lister(),
		operatorClient:            operatorClient,
		eventRecorder:             eventRecorder,
		scStateEvaluator:          evaluator,
		optionalStorageClassHooks: optionalStorageClassHooks,
	}

	return factory.New().WithSync(
		c.Sync,
	).ResyncEvery(
		time.Minute,
	).WithSyncDegradedOnError(
		operatorClient,
	).WithInformers(
		operatorClient.Informer(),
		informerFactory.Storage().V1().StorageClasses().Informer(),
		operatorInformer.Operator().V1().ClusterCSIDrivers().Informer(),
	).ToController(
		"StorageClassController",
		eventRecorder,
	)
}

func (c *CSIStorageClassController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	klog.V(4).Infof("StorageClassController sync started")
	defer klog.V(4).Infof("StorageClassController sync finished")

	opSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	if opSpec.ManagementState != operatorapi.Managed {
		return nil
	}

	for _, file := range c.files {
		if err := c.syncStorageClass(ctx, opSpec, file); err != nil {
			return err
		}
	}

	return nil
}

func (c *CSIStorageClassController) syncStorageClass(ctx context.Context, opSpec *operatorapi.OperatorSpec, assetFile string) error {
	expectedScBytes, err := c.assetFunc(assetFile)
	if err != nil {
		return err
	}

	expectedSC := resourceread.ReadStorageClassV1OrDie(expectedScBytes)

	for i := range c.optionalStorageClassHooks {
		err := c.optionalStorageClassHooks[i](opSpec, expectedSC)
		if err != nil {
			return fmt.Errorf("error running hook function (index=%d): %w", i, err)
		}
	}

	err = SetDefaultStorageClass(c.storageClassLister, expectedSC)
	if err != nil {
		return err
	}

	return c.scStateEvaluator.EvalAndApplyStorageClass(ctx, expectedSC)
}

func SetDefaultStorageClass(storageClassLister v1.StorageClassLister, storageClass *storagev1.StorageClass) error {
	existingSCs, err := storageClassLister.List(labels.Everything())
	if err != nil {
		return err
	}

	defaultSCCount := 0
	annotationKeyPresent := false
	// Skip the default SC annotation check if it's not in the input/expectedSC.
	if storageClass.Annotations != nil && storageClass.Annotations[defaultScAnnotationKey] != "" {
		for _, sc := range existingSCs {
			if sc.Annotations[defaultScAnnotationKey] == "true" && sc.Name != storageClass.Name {
				defaultSCCount++
			}
			if sc.Name == storageClass.Name && sc.Annotations != nil {
				// There already is an SC with same name we intend to apply, copy its annotation.
				if val, ok := sc.Annotations[defaultScAnnotationKey]; ok {
					storageClass.Annotations[defaultScAnnotationKey] = val
					annotationKeyPresent = true // If there is a key, we need to preserve it, whatever the value is.
				} else {
					annotationKeyPresent = false
				}
				storageClass.ObjectMeta.ResourceVersion = sc.ObjectMeta.ResourceVersion
			}
		}
		// There already is a default, and it's not set on the SC we intend to apply. Also, if there is any value for
		// defaultScAnnotationKey do not overwrite it (empty string is a correct value).
		if defaultSCCount > 0 && !annotationKeyPresent {
			storageClass.Annotations[defaultScAnnotationKey] = "false"
		}
	}
	return nil
}

// UpdateConditionFunc returns a func to update a condition.
func removeConditionFn(condType string) v1helpers.UpdateStatusFunc {
	return func(oldStatus *operatorapi.OperatorStatus) error {
		v1helpers.RemoveOperatorCondition(&oldStatus.Conditions, condType)
		return nil
	}
}

// StorageClassStateEvaluator evaluates the StorageClassState in the corresponding
// ClusterCSIDriver and reconciles the StorageClass according to that policy.
type StorageClassStateEvaluator struct {
	kubeClient             kubernetes.Interface
	clusterCSIDriverLister oplisters.ClusterCSIDriverLister
	operatorClient         v1helpers.OperatorClient
	eventRecorder          events.Recorder
}

func NewStorageClassStateEvaluator(
	kubeClient kubernetes.Interface,
	clusterCSIDriverLister oplisters.ClusterCSIDriverLister,
	eventRecorder events.Recorder) *StorageClassStateEvaluator {
	return &StorageClassStateEvaluator{
		kubeClient:             kubeClient,
		clusterCSIDriverLister: clusterCSIDriverLister,
		eventRecorder:          eventRecorder,
	}
}

// GetStorageClassState accepts the name of a ClusterCSIDriver and returns the
// StorageClassState associated with that object. If the ClusterCSIDriver is not
// found, this function returns the default state (Managed).
func (e *StorageClassStateEvaluator) GetStorageClassState(ccdName string) operatorapi.StorageClassStateName {
	scState := operatorapi.ManagedStorageClass
	clusterCSIDriver, err := e.clusterCSIDriverLister.Get(ccdName)
	if err != nil {
		klog.V(4).Infof("failed to get ClusterCSIDriver %s, assuming Managed StorageClassState: %v", ccdName, err)
	} else {
		scState = clusterCSIDriver.Spec.StorageClassState
	}
	return scState
}

// ApplyStorageClass applies the provided SC according to the StorageClassState.
// If Managed, apply the SC. If Unmanaged, do nothing. If Removed, delete the SC.
func (e *StorageClassStateEvaluator) ApplyStorageClass(ctx context.Context, expectedSC *storagev1.StorageClass, scState operatorapi.StorageClassStateName) (err error) {
	// StorageClassState determines how the SC is reconciled.
	switch scState {
	case operatorapi.ManagedStorageClass, "":
		// managed: apply SC
		_, _, err = resourceapply.ApplyStorageClass(ctx, e.kubeClient.StorageV1(), e.eventRecorder, expectedSC)
	case operatorapi.UnmanagedStorageClass:
		// unmanaged: do nothing
	case operatorapi.RemovedStorageClass:
		// remove: delete SC
		_, _, err = resourceapply.DeleteStorageClass(ctx, e.kubeClient.StorageV1(), e.eventRecorder, expectedSC)
	default:
		err = fmt.Errorf("invalid StorageClassState %s", scState)
	}
	return err
}

func (e *StorageClassStateEvaluator) EvalAndApplyStorageClass(ctx context.Context, expectedSC *storagev1.StorageClass) error {
	scState := e.GetStorageClassState(expectedSC.Provisioner)
	return e.ApplyStorageClass(ctx, expectedSC, scState)
}

func (e *StorageClassStateEvaluator) IsManaged(scState operatorapi.StorageClassStateName) bool {
	return (scState == operatorapi.ManagedStorageClass || scState == "")
}
