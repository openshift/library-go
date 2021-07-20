package startupmonitor

import (
	"fmt"
	"io/fs"
	"os"
	"testing"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"k8s.io/apimachinery/pkg/api/equality"
)

var samplePod = `
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
`

func TestFindPreviousRevision(t *testing.T) {
	scenarios := []struct {
		name   string
		fakeIO *fakeIO

		expectedPrevRev int
		expectedErr     string
		expectedFound   bool
	}{
		{
			name: "ReadDir error",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return nil, fmt.Errorf("fake error")
				},
			},
			expectedErr: "fake error",
		},

		{
			name: "ReadDir returns empty result",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return nil, nil
				},
			},
		},

		{
			name: "ReadDir returns files only",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeFile("kube-apiserver-pod-11"), fakeFile("kube-apiserver-pod-12")}, nil
				},
			},
		},

		{
			name: "ReadDir returns a directory that doesn't match prefix",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-abc-apiserver-pod-11")}, nil
				},
			},
		},

		{
			name: "ReadDir returns a directory that has incorrect revision",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-pod-FF")}, nil
				},
			},
			expectedFound: false,
		},

		{
			name: "ReadDir returns a single directory",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-pod-11")}, nil
				},
			},
			expectedPrevRev: 11,
			expectedFound:   true,
		},

		{
			name: "ReadDir returns only current",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-pod-8")}, nil
				},
			},
		},

		{
			name: "prev rev found",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-pod-4"), fakeDir("kube-apiserver-pod-8"), fakeDir("kube-apiserver-pod-5")}, nil
				},
			},
			expectedPrevRev: 5,
			expectedFound:   true,
		},

		{
			name: "prev rev found with sort",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-pod-5"), fakeDir("kube-apiserver-pod-8"), fakeDir("kube-apiserver-pod-4")}, nil
				},
			},
			expectedPrevRev: 5,
			expectedFound:   true,
		},

		{
			name: "prev rev found with files that match the prefix",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-pod-12"), fakeDir("kube-apiserver-pod-11"), fakeFile("kube-apiserver-pod-13"), fakeFile("kube-apiserver-pod-14")}, nil
				},
			},
			expectedPrevRev: 12,
			expectedFound:   true,
		},

		{
			name: "ReadDir returns another directory that has incorrect revision",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-pod-abc-11")}, nil
				},
			},
		},

		{
			name: "only directories with kube-apiserver-pod prefix are considered",
			fakeIO: &fakeIO{
				ExpectedReadDirFnCounter: 1,
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-certs"), fakeDir("kube-apiserver-7"), fakeDir("kube-apiserver-11"), fakeDir("kube-apiserver-pod-0"), fakeDir("kube-apiserver-pod-1")}, nil
				},
			},
			expectedPrevRev: 1,
			expectedFound:   true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			target := createTestFallback(scenario.fakeIO)

			// act
			prevRev, found, err := target.findPreviousRevision()

			// validate
			if err := scenario.fakeIO.Validate(); err != nil {
				t.Error(err)
			}
			if prevRev != scenario.expectedPrevRev {
				t.Errorf("unexpected prevRev %d, expected %d", prevRev, scenario.expectedPrevRev)
			}
			if found != scenario.expectedFound {
				t.Errorf("unexpected found %v, expected %v", found, scenario.expectedFound)
			}
			validateError(t, err, scenario.expectedErr)
		})
	}
}

func TestCreateLastKnowGoodRevisionFor(t *testing.T) {
	scenarios := []struct {
		name      string
		fakeIO    *fakeIO
		expectErr string
	}{
		// scenario 1
		{
			name: "step 0: is a dir",
			fakeIO: &fakeIO{
				ExpectedStatFnCounter: 1,
				StatFn: func(path string) (os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return fakeDir("fake-directory"), nil
				},
			},
			expectErr: "the provided path /etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good is incorrect and points to a directory",
		},

		// scenario 2
		{
			name: "step 0: rm fails",
			fakeIO: &fakeIO{
				ExpectedStatFnCounter:   1,
				ExpectedRemoveFnCounter: 1,

				StatFn: func(path string) (os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return fakeFile("fake-file"), nil
				},
				RemoveFn: func(path string) error {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return fmt.Errorf("unexpected path %s", path)
					}
					return fmt.Errorf("fake error")
				},
			},
			expectErr: "fake error",
		},

		// scenario 3
		{
			name: "step 0: !IsNotExists",
			fakeIO: &fakeIO{
				ExpectedStatFnCounter: 1,
				StatFn: func(path string) (os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return fakeFile("fake-file"), fmt.Errorf("fake error")
				},
			},
			expectErr: "fake error",
		},

		// scenario 4
		{
			name: "step 1: SymLink err",
			fakeIO: &fakeIO{
				ExpectedStatFnCounter:    1,
				ExpectedSymlinkFnCounter: 1,
				StatFn: func(path string) (os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return fakeFile("fake-file"), os.ErrNotExist
				},
				SymlinkFn: func(oldname, newname string) error {
					if oldname != "/etc/kubernetes/static-pod-resources/kube-apiserver-pod-8/kube-apiserver-pod.yaml" {
						return fmt.Errorf("unexpected oldname %s", oldname)
					}
					if newname != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return fmt.Errorf("unexpected newname %s", newname)
					}
					return fmt.Errorf("fake err")
				},
			},
			expectErr: `failed to create a symbolic link "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" for "/etc/kubernetes/static-pod-resources/kube-apiserver-pod-8/kube-apiserver-pod.yaml" due to fake err`,
		},

		// scenario 5
		{
			name: "happy path",
			fakeIO: &fakeIO{
				ExpectedStatFnCounter:    1,
				ExpectedSymlinkFnCounter: 1,
				ExpectedRemoveFnCounter:  0,
				StatFn: func(path string) (os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return fakeFile("fake-file"), os.ErrNotExist
				},
				SymlinkFn: func(oldname, newname string) error {
					if oldname != "/etc/kubernetes/static-pod-resources/kube-apiserver-pod-8/kube-apiserver-pod.yaml" {
						return fmt.Errorf("unexpected oldname %s", oldname)
					}
					if newname != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return fmt.Errorf("unexpected newname %s", newname)
					}
					return nil
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			target := createTestFallback(scenario.fakeIO)

			// act
			err := target.createLastKnowGoodRevisionFor(target.revision, true)

			// validate
			validateError(t, err, scenario.expectErr)
			if err := scenario.fakeIO.Validate(); err != nil {
				t.Error(err)
			}

			if scenario.fakeIO.ExpectedStatFnCounter != scenario.fakeIO.StatFnCounter {
				t.Errorf("unexpected StatFn inovations %d, expeccted %d", scenario.fakeIO.StatFnCounter, scenario.fakeIO.ExpectedStatFnCounter)
			}
			if scenario.fakeIO.ExpectedSymlinkFnCounter != scenario.fakeIO.SymlinkFnCounter {
				t.Errorf("unexpected SymlinkFn inovations %d, expeccted %d", scenario.fakeIO.SymlinkFnCounter, scenario.fakeIO.ExpectedSymlinkFnCounter)
			}
			if scenario.fakeIO.ExpectedRemoveFnCounter != scenario.fakeIO.RemoveFnCounter {
				t.Errorf("unexpected RemoveFn inovations %d, expeccted %d", scenario.fakeIO.RemoveFnCounter, scenario.fakeIO.ExpectedRemoveFnCounter)
			}

		})
	}
}

func TestFallbackToPreviousRevision(t *testing.T) {
	scenarios := []struct {
		name        string
		fakeIO      *fakeIO
		expectedErr string
	}{
		// scenario 1
		{
			name: "happy path",
			fakeIO: &fakeIO{
				ExpectedStatFnCounter: 1, ExpectedReadFileFnCounter: 1, ExpectedWriteFileFnCounter: 1, ExpectedRemoveFnCounter: 1,
				StatFn: func(path string) (os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return fakeFile("/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good"), nil
				},
				ReadFileFn: func(path string) ([]byte, error) {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return nil, fmt.Errorf("unexpected path %s", path)
					}
					return []byte(samplePod), nil
				},
				WriteFileFn: func(filename string, data []byte, perm fs.FileMode) error {
					if filename != "/etc/kubernetes/manifests/kube-apiserver-pod.yaml" {
						return fmt.Errorf("unexpected path %s", filename)
					}
					actualPod, err := resourceread.ReadPodV1(data)
					if err != nil {
						return err
					}
					expectedPod, err := resourceread.ReadPodV1([]byte(samplePod))
					if err != nil {
						return err
					}
					expectedPod.UID = actualPod.UID
					expectedPod.Annotations = map[string]string{}
					expectedPod.Annotations["startup-monitor.static-pods.openshift.io/fallback-for-revision"] = "8"
					expectedPod.Annotations["startup-monitor.static-pods.openshift.io/fallback-reason"] = "SomeReason"
					expectedPod.Annotations["startup-monitor.static-pods.openshift.io/fallback-message"] = "Some message for the user"

					if !equality.Semantic.DeepEqual(actualPod, expectedPod) {
						return fmt.Errorf("unexpected pod was written")
					}
					return nil
				},
			},
		},

		// scenario 2
		{
			name: "last known doesn't exist",
			fakeIO: &fakeIO{
				ExpectedStatFnCounter: 2, ExpectedReadDirFnCounter: 1, ExpectedWriteFileFnCounter: 1, ExpectedRemoveFnCounter: 1, ExpectedReadFileFnCounter: 1, ExpectedSymlinkFnCounter: 1,
				StatFn: func(path string) (os.FileInfo, error) {
					switch path {
					case "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good":
						return nil, os.ErrNotExist
					case "/etc/kubernetes/static-pod-resources/kube-apiserver-pod-7/kube-apiserver-pod.yaml":
						return fakeFile("/etc/kubernetes/static-pod-resources/kube-apiserver-pod-7/kube-apiserver-pod.yaml"), nil
					case "/etc/kubernetes/static-pod-resources/kube-apiserver-pod-9/kube-apiserver-pod.yaml":
						return fakeFile("/etc/kubernetes/static-pod-resources/kube-apiserver-pod-9/kube-apiserver-pod.yaml"), nil
					case "/etc/kubernetes/static-pod-resources/kube-apiserver-pod-12/kube-apiserver-pod.yaml":
						return fakeFile("/etc/kubernetes/static-pod-resources/kube-apiserver-pod-12/kube-apiserver-pod.yaml"), nil
					default:
						return nil, fmt.Errorf("unexpected StatFn path %s", path)
					}
				},
				ReadDirFn: func(path string) ([]os.FileInfo, error) {
					if path != "/etc/kubernetes/static-pod-resources" {
						return nil, fmt.Errorf("unexpected ReadDirFn path %s", path)
					}
					return []os.FileInfo{fakeDir("kube-apiserver-pod-7"), fakeDir("kube-apiserver-pod-12"), fakeDir("kube-apiserver-pod-9")}, nil
				},
				SymlinkFn: func(oldname, newname string) error {
					if oldname != "/etc/kubernetes/static-pod-resources/kube-apiserver-pod-12/kube-apiserver-pod.yaml" {
						return fmt.Errorf("unexpected SymlinkFnoldname %s", oldname)
					}
					if newname != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return fmt.Errorf("unexpected SymlinkFn newname %s", newname)
					}
					return nil
				},
				ReadFileFn: func(path string) ([]byte, error) {
					if path != "/etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good" {
						return nil, fmt.Errorf("unexpected ReadFileFnpath %s", path)
					}
					return []byte(samplePod), nil
				},
				WriteFileFn: func(filename string, data []byte, perm fs.FileMode) error {
					if filename != "/etc/kubernetes/manifests/kube-apiserver-pod.yaml" {
						return fmt.Errorf("unexpected WriteFileFnpath %s", filename)
					}
					actualPod, err := resourceread.ReadPodV1(data)
					if err != nil {
						return err
					}
					expectedPod, err := resourceread.ReadPodV1([]byte(samplePod))
					if err != nil {
						return err
					}
					expectedPod.UID = actualPod.UID
					expectedPod.Annotations = map[string]string{}
					expectedPod.Annotations["startup-monitor.static-pods.openshift.io/fallback-for-revision"] = "8"
					expectedPod.Annotations["startup-monitor.static-pods.openshift.io/fallback-reason"] = "SomeReason"
					expectedPod.Annotations["startup-monitor.static-pods.openshift.io/fallback-message"] = "Some message for the user"
					if !equality.Semantic.DeepEqual(actualPod, expectedPod) {
						return fmt.Errorf("unexpected WriteFileFn pod was written")
					}
					return nil
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			target := createTestFallback(scenario.fakeIO)

			// act
			err := target.fallbackToPreviousRevision("SomeReason", "Some message for the user")
			validateError(t, err, scenario.expectedErr)
			if err := scenario.fakeIO.Validate(); err != nil {
				t.Error(err)
			}
		})
	}
}

func createTestFallback(fakeIO *fakeIO) *staticPodFallback {
	target := newStaticPodFallback()
	target.io = fakeIO
	target.revision = 8
	target.targetName = "kube-apiserver"
	target.staticPodResourcesPath = "/etc/kubernetes/static-pod-resources"
	target.manifestsPath = "/etc/kubernetes/manifests"
	return target
}
