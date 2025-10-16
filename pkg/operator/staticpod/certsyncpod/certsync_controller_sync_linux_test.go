//go:build linux

package certsyncpod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/installer"
	adtesting "github.com/openshift/library-go/pkg/operator/staticpod/internal/atomicdir/testing"
)

const testingNamespace = "test-namespace"

// TestCertSyncController_Sync tests the sync method in various scenarios.
func TestCertSyncController_Sync(t *testing.T) {
	testCases := []struct {
		name               string
		configMapsToSync   []installer.UnrevisionedResource
		configMapObjects   []*corev1.ConfigMap
		configMapGetErrors map[string]error
		secretsToSync      []installer.UnrevisionedResource
		secretObjects      []*corev1.Secret
		secretGetErrors    map[string]error
		// Keys are paths relative to the controller destination directory.
		existingDirectories map[string]adtesting.DirectoryState
		expectedError       bool
		expectedEventTypes  []string
		// Keys are paths relative to the controller destination directory.
		expectedDirectories map[string]adtesting.DirectoryState
	}{
		{
			name: "create first configmap",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "test-config"},
			},
			configMapObjects: []*corev1.ConfigMap{
				createConfigMap("test-config", map[string]string{
					"config.yaml": "test-config-content",
				}),
			},
			expectedEventTypes: []string{"CertificateUpdated"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config": {
					"config.yaml": {
						Content: []byte("test-config-content"),
						Perm:    0644,
					},
				},
			},
		},
		{
			name: "add another configmap",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "test-config-1"},
				{Name: "test-config-2"},
			},
			configMapObjects: []*corev1.ConfigMap{
				createConfigMap("test-config-1", map[string]string{
					"config.yaml": "test-config-content-1",
				}),
				createConfigMap("test-config-2", map[string]string{
					"config.yaml": "test-config-content-2",
				}),
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config-1": {
					"config.yaml": {
						Content: []byte("test-config-content-1"),
						Perm:    0644,
					},
				},
			},
			expectedEventTypes: []string{"CertificateUpdated"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config-1": {
					"config.yaml": {
						Content: []byte("test-config-content-1"),
						Perm:    0644,
					},
				},
				"configmaps/test-config-2": {
					"config.yaml": {
						Content: []byte("test-config-content-2"),
						Perm:    0644,
					},
				},
			},
		},
		{
			name: "update existing configmap",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "test-config", Optional: false},
			},
			configMapObjects: []*corev1.ConfigMap{
				createConfigMap("test-config", map[string]string{
					"config.yaml": "updated-config-content",
				}),
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config": {
					"config.yaml": {
						Content: []byte("test-config-content"),
						Perm:    0644,
					},
				},
			},
			expectedEventTypes: []string{"CertificateUpdated"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config": {
					"config.yaml": {
						Content: []byte("updated-config-content"),
						Perm:    0644,
					},
				},
			},
		},
		{
			name: "succeed when optional configmap missing",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "optional-config", Optional: true},
			},
		},
		{
			name: "fail when required configmap missing",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "required-config", Optional: false},
			},
			expectedError: true,
		},
		{
			name: "remove directory when optional configmap missing",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "optional-config", Optional: true},
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"configmaps/optional-config": {
					"config.yaml": {
						Content: []byte("optional-config-content"),
						Perm:    0644,
					},
				},
			},
			expectedEventTypes: []string{"CertificateRemoved"},
		},
		{
			name: "configmap unchanged on get error",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "error-config"},
			},
			configMapObjects: []*corev1.ConfigMap{
				createConfigMap("error-config", map[string]string{
					"config.yaml": "updated-config-content",
				}),
			},
			configMapGetErrors: map[string]error{
				"error-config": apierrors.NewInternalError(fmt.Errorf("API server error")),
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"configmaps/error-config": {
					"config.yaml": {
						Content: []byte("error-config-content"),
						Perm:    0644,
					},
				},
			},
			expectedError:      true,
			expectedEventTypes: []string{"CertificateUpdateFailed"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"configmaps/error-config": {
					"config.yaml": {
						Content: []byte("error-config-content"),
						Perm:    0644,
					},
				},
			},
		},

		{
			name: "create first secret",
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "test-secret"},
			},
			secretObjects: []*corev1.Secret{
				createSecret("test-secret", map[string][]byte{
					"tls.crt": []byte("test-cert-content"),
					"tls.key": []byte("test-key-content"),
				}),
			},
			expectedEventTypes: []string{"CertificateUpdated"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"secrets/test-secret": {
					"tls.crt": {
						Content: []byte("test-cert-content"),
						Perm:    0600,
					},
					"tls.key": {
						Content: []byte("test-key-content"),
						Perm:    0600,
					},
				},
			},
		},
		{
			name: "add another secret",
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "test-secret-1"},
				{Name: "test-secret-2"},
			},
			secretObjects: []*corev1.Secret{
				createSecret("test-secret-1", map[string][]byte{
					"tls-1.crt": []byte("test-cert-content-1"),
					"tls-1.key": []byte("test-key-content-1"),
				}),
				createSecret("test-secret-2", map[string][]byte{
					"tls-2.crt": []byte("test-cert-content-2"),
					"tls-2.key": []byte("test-key-content-2"),
				}),
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"secrets/test-secret-1": {
					"tls-1.crt": {
						Content: []byte("test-cert-content-1"),
						Perm:    0600,
					},
					"tls-1.key": {
						Content: []byte("test-key-content-1"),
						Perm:    0600,
					},
				},
			},
			expectedEventTypes: []string{"CertificateUpdated"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"secrets/test-secret-1": {
					"tls-1.crt": {
						Content: []byte("test-cert-content-1"),
						Perm:    0600,
					},
					"tls-1.key": {
						Content: []byte("test-key-content-1"),
						Perm:    0600,
					},
				},
				"secrets/test-secret-2": {
					"tls-2.crt": {
						Content: []byte("test-cert-content-2"),
						Perm:    0600,
					},
					"tls-2.key": {
						Content: []byte("test-key-content-2"),
						Perm:    0600,
					},
				},
			},
		},
		{
			name: "update existing secret",
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "test-secret", Optional: true},
			},
			secretObjects: []*corev1.Secret{
				createSecret("test-secret", map[string][]byte{
					"tls.crt": []byte("updated-cert-content"),
					"tls.key": []byte("updated-key-content"),
				}),
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"secrets/test-secret": {
					"tls.crt": {
						Content: []byte("test-cert-content"),
						Perm:    0600,
					},
					"tls.key": {
						Content: []byte("test-key-content"),
						Perm:    0600,
					},
				},
			},
			expectedEventTypes: []string{"CertificateUpdated"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"secrets/test-secret": {
					"tls.crt": {
						Content: []byte("updated-cert-content"),
						Perm:    0600,
					},
					"tls.key": {
						Content: []byte("updated-key-content"),
						Perm:    0600,
					},
				},
			},
		},
		{
			name: "succeed when optional secret missing",
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "optional-secret", Optional: true},
			},
		},
		{
			name: "fail when required secret missing",
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "required-secret", Optional: false},
			},
			expectedError: true,
		},
		{
			name: "remove directory when optional secret missing",
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "optional-secret", Optional: true},
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"secrets/optional-secret": {
					"tls.crt": {
						Content: []byte("test-cert-content"),
						Perm:    0600,
					},
					"tls.key": {
						Content: []byte("test-key-content"),
						Perm:    0600,
					},
				},
			},
			expectedEventTypes: []string{"CertificateRemoved"},
		},
		{
			name: "secret unchanged on get error",
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "error-secret"},
			},
			secretObjects: []*corev1.Secret{
				createSecret("error-secret", map[string][]byte{
					"token": []byte("updated-secret-content"),
				}),
			},
			secretGetErrors: map[string]error{
				"error-secret": apierrors.NewInternalError(fmt.Errorf("API server error")),
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"secrets/error-secret": {
					"token": {
						Content: []byte("error-config-content"),
						Perm:    0600,
					},
				},
			},
			expectedError:      true,
			expectedEventTypes: []string{"CertificateUpdateFailed"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"secrets/error-secret": {
					"token": {
						Content: []byte("error-config-content"),
						Perm:    0600,
					},
				},
			},
		},

		{
			name: "create multiple configmaps and secrets",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "test-config-1", Optional: false},
				{Name: "test-config-2", Optional: true},
			},
			configMapObjects: []*corev1.ConfigMap{
				createConfigMap("test-config-1", map[string]string{
					"app.yaml": "test-config-content-1",
				}),
				createConfigMap("test-config-2", map[string]string{
					"opt.yaml": "test-config-content-2",
				}),
			},
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "test-secret-1", Optional: false},
				{Name: "test-secret-2", Optional: true},
			},
			secretObjects: []*corev1.Secret{
				createSecret("test-secret-1", map[string][]byte{
					"token": []byte("test-secret-content-1"),
				}),
				createSecret("test-secret-2", map[string][]byte{
					"key": []byte("test-secret-content-2"),
				}),
			},
			expectedEventTypes: []string{"CertificateUpdated", "CertificateUpdated", "CertificateUpdated", "CertificateUpdated"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config-1": {
					"app.yaml": {
						Content: []byte("test-config-content-1"),
						Perm:    0644,
					},
				},
				"configmaps/test-config-2": {
					"opt.yaml": {
						Content: []byte("test-config-content-2"),
						Perm:    0644,
					},
				},
				"secrets/test-secret-1": {
					"token": {
						Content: []byte("test-secret-content-1"),
						Perm:    0600,
					},
				},
				"secrets/test-secret-2": {
					"key": {
						Content: []byte("test-secret-content-2"),
						Perm:    0600,
					},
				},
			},
		},
		{
			name: "create scripts",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "test-config-script"},
			},
			configMapObjects: []*corev1.ConfigMap{
				createConfigMap("test-config-script", map[string]string{
					"run.sh": "sleep infinity",
				}),
			},
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "test-secret-script"},
			},
			secretObjects: []*corev1.Secret{
				createSecret("test-secret-script", map[string][]byte{
					"run.sh": []byte("sleep infinity"),
				}),
			},
			expectedEventTypes: []string{"CertificateUpdated", "CertificateUpdated"},
			expectedDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config-script": {
					"run.sh": {
						Content: []byte("sleep infinity"),
						Perm:    0755, // .sh file extension causes +x
					},
				},
				"secrets/test-secret-script": {
					"run.sh": {
						Content: []byte("sleep infinity"),
						Perm:    0711, // .sh file extension causes +x
					},
				},
			},
		},
		{
			name: "already synchronized",
			configMapsToSync: []installer.UnrevisionedResource{
				{Name: "test-config"},
			},
			configMapObjects: []*corev1.ConfigMap{
				createConfigMap("test-config", map[string]string{
					"config.yaml": "test-config-content",
				}),
			},
			secretsToSync: []installer.UnrevisionedResource{
				{Name: "test-secret"},
			},
			secretObjects: []*corev1.Secret{
				createSecret("test-secret", map[string][]byte{
					"tls.crt": []byte("test-cert-content"),
					"tls.key": []byte("test-key-content"),
				}),
			},
			existingDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config": {
					"config.yaml": {
						Content: []byte("test-config-content"),
						Perm:    0644,
					},
				},
				"secrets/test-secret": {
					"tls.crt": {
						Content: []byte("test-cert-content"),
						Perm:    0600,
					},
					"tls.key": {
						Content: []byte("test-key-content"),
						Perm:    0600,
					},
				},
			},
			expectedEventTypes: nil, // No events when no changes.
			expectedDirectories: map[string]adtesting.DirectoryState{
				"configmaps/test-config": {
					"config.yaml": {
						Content: []byte("test-config-content"),
						Perm:    0644,
					},
				},
				"secrets/test-secret": {
					"tls.crt": {
						Content: []byte("test-cert-content"),
						Perm:    0600,
					},
					"tls.key": {
						Content: []byte("test-key-content"),
						Perm:    0600,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			controller, eventRecorder, stopCh := createController(t.TempDir(),
				tc.configMapsToSync, tc.configMapObjects, tc.configMapGetErrors,
				tc.secretsToSync, tc.secretObjects, tc.secretGetErrors,
			)
			defer close(stopCh)

			for path, state := range tc.existingDirectories {
				targetPath := filepath.Join(controller.destinationDir, path)
				state.Write(t, targetPath, 0755)
			}

			syncCtx := factory.NewSyncContext("CertSyncController", eventRecorder)
			err := controller.sync(context.Background(), syncCtx)
			if err != nil {
				t.Log("sync returned an error:", err)
			}

			if tc.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tc.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			verifyEvents(t, eventRecorder, tc.expectedEventTypes)

			// Check filesystem state. We need to gather all paths to know which are extra.
			extraPaths := sets.NewString()
			filepath.Walk(controller.destinationDir, func(path string, info os.FileInfo, err error) error {
				if !info.IsDir() ||
					path == controller.destinationDir ||
					strings.HasSuffix(path, "/staging") ||
					strings.HasSuffix(path, "/staging/cert-sync") ||
					strings.HasSuffix(path, "/staging/cert-sync/secrets") ||
					strings.HasSuffix(path, "/staging/cert-sync/configmaps") ||
					path == filepath.Join(controller.destinationDir, "configmaps") ||
					path == filepath.Join(controller.destinationDir, "secrets") {

					return nil
				}

				extraPaths.Insert(path)
				return nil
			})
			for path, state := range tc.expectedDirectories {
				targetPath := filepath.Join(controller.destinationDir, path)
				state.CheckDirectoryMatches(t, targetPath, 0755)
				extraPaths.Delete(targetPath)
			}
			if extraPaths.Len() > 0 {
				t.Errorf("Directories that should not be there detected: %v", extraPaths.List())
			}
		})
	}
}

func createController(
	destinationDir string,
	configMapsToSync []installer.UnrevisionedResource,
	configMapObjects []*corev1.ConfigMap,
	configMapGetErrors map[string]error,
	secretsToSync []installer.UnrevisionedResource,
	secretObjects []*corev1.Secret,
	secretGetErrors map[string]error,
) (*CertSyncController, events.Recorder, chan struct{}) {
	kubeObjects := make([]runtime.Object, 0)
	for _, cm := range configMapObjects {
		kubeObjects = append(kubeObjects, cm)
	}
	for _, secret := range secretObjects {
		kubeObjects = append(kubeObjects, secret)
	}
	kubeClient := fake.NewClientset(kubeObjects...)

	if configMapGetErrors != nil {
		kubeClient.PrependReactor("get", "configmaps", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
			getAction := action.(ktesting.GetAction)
			if err, exists := configMapGetErrors[getAction.GetName()]; exists {
				return true, nil, err
			}
			return false, nil, nil
		})
	}

	if secretGetErrors != nil {
		kubeClient.PrependReactor("get", "secrets", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
			getAction := action.(ktesting.GetAction)
			if err, exists := secretGetErrors[getAction.GetName()]; exists {
				return true, nil, err
			}
			return false, nil, nil
		})
	}

	informers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Hour)
	eventRecorder := events.NewInMemoryRecorder("CertSyncController", clocktesting.NewFakeClock(time.Now()))

	controller := &CertSyncController{
		destinationDir:  destinationDir,
		namespace:       testingNamespace,
		configMaps:      configMapsToSync,
		secrets:         secretsToSync,
		configMapGetter: kubeClient.CoreV1().ConfigMaps(testingNamespace),
		configMapLister: informers.Core().V1().ConfigMaps().Lister(),
		secretGetter:    kubeClient.CoreV1().Secrets(testingNamespace),
		secretLister:    informers.Core().V1().Secrets().Lister(),
		eventRecorder:   eventRecorder,
	}

	stopCh := make(chan struct{})
	informers.Start(stopCh)
	informers.WaitForCacheSync(stopCh)

	return controller, eventRecorder, stopCh
}

func verifyEvents(t *testing.T, eventRecorder events.Recorder, expectedEventTypes []string) {
	var gotEventTypes []string
	for _, event := range eventRecorder.(events.InMemoryRecorder).Events() {
		gotEventTypes = append(gotEventTypes, event.Reason)
	}

	if !cmp.Equal(gotEventTypes, expectedEventTypes) {
		t.Errorf("Unexpected event types (-want, +got): \n%v", cmp.Diff(expectedEventTypes, gotEventTypes))
	}
}

func createConfigMap(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testingNamespace,
		},
		Data: data,
	}
}

func createSecret(name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testingNamespace,
		},
		Data: data,
	}
}
