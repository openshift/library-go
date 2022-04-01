package csistorageclasscontroller

import (
	"context"
	"github.com/google/go-cmp/cmp"
	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers"
	v1 "k8s.io/client-go/informers/storage/v1"
	"k8s.io/client-go/kubernetes"
	fakecore "k8s.io/client-go/kubernetes/fake"
	"testing"
)

const (
	controllerName = "TestCSIStorageClassController"
	operandName    = "test-csi-storage-class-controller"
)

type testCase struct {
	name              string
	initialObjects    testObjects
	expectedObjects   testObjects
	appliedAnnotation string
	expectErr         bool
}

type testObjects struct {
	storageClasses []*storagev1.StorageClass
}

type testContext struct {
	controller     factory.Controller
	operatorClient v1helpers.OperatorClient
	kubeClient     kubernetes.Interface
	scInformer     v1.StorageClassInformer
}

// defaultScAnnotation accepts values "true", "false", ""
func fakeAssetFuncFactory(defaultScAnnotation string) resourceapply.AssetFunc {
	switch defaultScAnnotation {
	case "true":
		return fakeAssetFuncDefaultSc
	case "false":
		return fakeAssetFuncNoDefaultSc
	default:
		return fakeAssetFuncAnnotationEmpty
	}
}

func fakeAssetFuncDefaultSc(filename string) ([]byte, error) {
	filename = ""
	storageClass := `
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: "test-apply-sc"
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: test.csi.example.com
parameters:
  type: available
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
`
	return []byte(storageClass), nil
}

func fakeAssetFuncNoDefaultSc(filename string) ([]byte, error) {
	filename = ""
	storageClass := `
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: "test-apply-sc"
  annotations:
    storageclass.kubernetes.io/is-default-class: "false"
provisioner: test.csi.example.com
parameters:
  type: available
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
`
	return []byte(storageClass), nil
}

func fakeAssetFuncAnnotationEmpty(filename string) ([]byte, error) {
	filename = ""
	storageClass := `
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: "test-apply-sc"
  annotations:
    storageclass.kubernetes.io/is-default-class: ""
provisioner: test.csi.example.com
parameters:
  type: available
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
`
	return []byte(storageClass), nil
}

func fakeAssetFuncToScObject(assetFunc func(string) ([]byte, error)) *storagev1.StorageClass {
	scBytes, err := assetFunc("filename")
	if err != nil {
		return nil
	}
	storageClassObject := resourceread.ReadStorageClassV1OrDie(scBytes)
	return storageClassObject
}

type driverModifier func(*fakeDriverInstance) *fakeDriverInstance

func makeFakeDriverInstance(modifiers ...driverModifier) *fakeDriverInstance {
	instance := &fakeDriverInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cluster",
			Generation: 0,
		},
		Spec: opv1.OperatorSpec{
			ManagementState: opv1.Managed,
		},
		Status: opv1.OperatorStatus{},
	}
	for _, modifier := range modifiers {
		instance = modifier(instance)
	}
	return instance
}

func newTestContext(test testCase, t *testing.T) *testContext {
	var initialObjects []runtime.Object
	for _, c := range test.initialObjects.storageClasses {
		initialObjects = append(initialObjects, c)
	}
	kubeClient := fakecore.NewSimpleClientset(initialObjects...)
	coreInformerFactory := coreinformers.NewSharedInformerFactory(kubeClient, 0 /*no resync */)
	scInformer := coreInformerFactory.Storage().V1().StorageClasses()

	if initialObjects != nil {
		for _, obj := range initialObjects {
			err := scInformer.Informer().GetIndexer().Add(obj)
			if err != nil {
				t.Error(err)
			}
		}
	}

	fakeDriver := makeFakeDriverInstance()
	fakeOperatorClient := v1helpers.NewFakeOperatorClient(&fakeDriver.Spec, &fakeDriver.Status, nil)

	controller := NewCSIStorageClassController(
		controllerName,
		fakeAssetFuncFactory(test.appliedAnnotation),
		"test",
		kubeClient,
		coreInformerFactory,
		fakeOperatorClient,
		events.NewInMemoryRecorder(operandName),
	)

	return &testContext{
		controller:     controller,
		operatorClient: fakeOperatorClient,
		kubeClient:     kubeClient,
		scInformer:     scInformer,
	}
}

func makeFakeScInstance(scName string, defaultSCAnnotation string) *storagev1.StorageClass {
	instance := &storagev1.StorageClass{
		TypeMeta: metav1.TypeMeta{
			Kind:       "StorageClass",
			APIVersion: "storage.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        scName,
			Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": defaultSCAnnotation},
		},
	}

	return instance
}

func TestSync(t *testing.T) {
	testCases := []testCase{
		{
			name: "test sync non-default sc - prior default is set - applied is not default",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "true"),
					makeFakeScInstance("test-sc-2", "false"),
				},
			},
			appliedAnnotation: "false", //Controls what default annotation value should sync try to apply.
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "true"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("false")),
				},
			},
		},
		{
			name: "test sync non-default sc - prior default is not set - applied is not default",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
				},
			},
			appliedAnnotation: "false",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("false")),
				},
			},
		},
		{
			name: "test sync non default sc - prior SC with same name is set - sync must not rewrite existing SC annotation",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("true")),
				},
			},
			appliedAnnotation: "false",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("true")),
				},
			},
		},
		{
			name: "test sync non default sc - prior SC with same has empty annotation - sync must not rewrite existing SC annotation",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("")),
				},
			},
			appliedAnnotation: "false",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("")),
				},
			},
		},
		{
			name: "test sync default sc - no prior default set - applied is default",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
				},
			},
			appliedAnnotation: "true",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("true")),
				},
			},
		},
		{
			name: "test sync default sc - prior default is set - applied is not default",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "true"),
					makeFakeScInstance("test-sc-2", "false"),
				},
			},
			appliedAnnotation: "true",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "true"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("false")),
				},
			},
		},
		{
			name: "test sync default sc - no prior sc - applied is default",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{},
			},
			appliedAnnotation: "true",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					fakeAssetFuncToScObject(fakeAssetFuncFactory("true")),
				},
			},
		},
		{
			name: "test sync default sc - prior SC with same name is non default - sync must not rewrite existing SC annotation",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("false")),
				},
			},
			appliedAnnotation: "true",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("false")),
				},
			},
		},
		{
			name: "test sync default sc - prior SC with same name has empty annotation - sync must not rewrite existing SC annotation",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("")),
				},
			},
			appliedAnnotation: "true",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "false"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("")),
				},
			},
		},
		{
			name: "test sync default sc - prior SC with same has empty annotation and another SC is default - sync must not rewrite existing SC annotation",
			initialObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "true"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("")),
				},
			},
			appliedAnnotation: "true",
			expectedObjects: testObjects{
				storageClasses: []*storagev1.StorageClass{
					makeFakeScInstance("test-sc", "true"),
					makeFakeScInstance("test-sc-2", "false"),
					fakeAssetFuncToScObject(fakeAssetFuncFactory("")),
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Initialize
			ctx := newTestContext(test, t)

			// Act
			err := ctx.controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder(operandName)))
			if err != nil {
				t.Errorf("Failed to sync StorageClass: %s", err)
			}

			// Assert
			actualSCList, _ := ctx.kubeClient.StorageV1().StorageClasses().List(context.TODO(), metav1.ListOptions{})
			actualSCs := map[string]*storagev1.StorageClass{}
			for i := range actualSCList.Items {
				sc := &actualSCList.Items[i]
				actualSCs[sc.Name] = sc
			}
			expectedSCs := map[string]*storagev1.StorageClass{}
			for _, sc := range test.expectedObjects.storageClasses {
				expectedSCs[sc.Name] = sc
			}

			for name, expectedSC := range expectedSCs {
				actualSC, found := actualSCs[name]
				if !found {
					t.Errorf("Expected StorageClass not found: %s", name)
					continue
				}
				if !equality.Semantic.DeepEqual(expectedSC, actualSC) {
					t.Errorf("Unexpected StorageClass %+v content:\n%s", name, cmp.Diff(expectedSC, actualSC))
				}
			}

		})
	}
}

// fakeInstance is a fake CSI driver instance that also fullfils the OperatorClient interface
type fakeDriverInstance struct {
	metav1.ObjectMeta
	Spec   opv1.OperatorSpec
	Status opv1.OperatorStatus
}
