package csistorageclasscontroller

import (
	"context"
	operatorapi "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/storage/v1"
	"k8s.io/klog/v2"
	"time"
)

const (
	defaultScAnnotationKey = "storageclass.kubernetes.io/is-default-class"
)

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
	file               string
	kubeClient         kubernetes.Interface
	storageClassLister v1.StorageClassLister
	operatorClient     v1helpers.OperatorClient
	eventRecorder      events.Recorder
}

func NewCSIStorageClassController(
	name string,
	assetFunc resourceapply.AssetFunc,
	file string,
	kubeClient kubernetes.Interface,
	informerFactory informers.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient,
	eventRecorder events.Recorder) factory.Controller {
	c := &CSIStorageClassController{
		name:               name,
		assetFunc:          assetFunc,
		file:               file,
		kubeClient:         kubeClient,
		storageClassLister: informerFactory.Storage().V1().StorageClasses().Lister(),
		operatorClient:     operatorClient,
		eventRecorder:      eventRecorder,
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

	syncErr := c.syncStorageClass(ctx)

	return syncErr
}

func (c *CSIStorageClassController) syncStorageClass(ctx context.Context) error {
	expectedScBytes, err := c.assetFunc(c.file)
	if err != nil {
		return err
	}

	expectedSC := resourceread.ReadStorageClassV1OrDie(expectedScBytes)

	existingSCs, err := c.storageClassLister.List(labels.Everything())
	if err != nil {
		klog.V(2).Infof("could not list StorageClass objects")
		return err
	}

	defaultSCCount := 0
	annotationKeyPresent := false
	// Skip the default SC annotation check if it's not in the input/expectedSC.
	if expectedSC.Annotations != nil && expectedSC.Annotations[defaultScAnnotationKey] != "" {
		for _, sc := range existingSCs {
			if sc.Annotations[defaultScAnnotationKey] == "true" && sc.Name != expectedSC.Name {
				defaultSCCount++
			}
			if sc.Name == expectedSC.Name && sc.Annotations != nil {
				// There already is an SC with same name we intend to apply, copy its annotation.
				if val, ok := sc.Annotations[defaultScAnnotationKey]; ok {
					expectedSC.Annotations[defaultScAnnotationKey] = val
					annotationKeyPresent = true // If there is a key, we need to preserve it, whatever the value is.
				} else {
					annotationKeyPresent = false
				}
			}
		}
		// There already is a default, and it's not set on the SC we intend to apply. Also, if there is any value for
		// defaultScAnnotationKey do not overwrite it (empty string is a correct value).
		if defaultSCCount > 0 && !annotationKeyPresent {
			expectedSC.Annotations[defaultScAnnotationKey] = "false"
		}
	}

	_, _, err = resourceapply.ApplyStorageClass(ctx, c.kubeClient.StorageV1(), c.eventRecorder, expectedSC)

	return err
}

// UpdateConditionFunc returns a func to update a condition.
func removeConditionFn(condType string) v1helpers.UpdateStatusFunc {
	return func(oldStatus *operatorapi.OperatorStatus) error {
		v1helpers.RemoveOperatorCondition(&oldStatus.Conditions, condType)
		return nil
	}
}
