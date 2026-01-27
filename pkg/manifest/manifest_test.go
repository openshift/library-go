package manifest

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"k8s.io/utils/ptr"

	"github.com/davecgh/go-spew/spew"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

func init() {
	klog.InitFlags(flag.CommandLine)
}

func TestParseManifests(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []Manifest
	}{{
		name: "ingress",
		raw: `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        backend:
          serviceName: test
          servicePort: 80
`,
		want: []Manifest{{
			id:  resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			Raw: []byte(`{"apiVersion":"extensions/v1beta1","kind":"Ingress","metadata":{"name":"test-ingress","namespace":"test-namespace"},"spec":{"rules":[{"http":{"paths":[{"backend":{"serviceName":"test","servicePort":80},"path":"/testpath"}]}}]}}`),
			GVK: schema.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "Ingress"},
		}},
	}, {
		name: "configmap",
		raw: `
apiVersion: v1
kind: ConfigMap
metadata:
  name: a-config
  namespace: default
data:
  color: "red"
  multi-line: |
    hello world
    how are you?
`,
		want: []Manifest{{
			id:  resourceId{Group: "", Kind: "ConfigMap", Name: "a-config", Namespace: "default"},
			Raw: []byte(`{"apiVersion":"v1","data":{"color":"red","multi-line":"hello world\nhow are you?\n"},"kind":"ConfigMap","metadata":{"name":"a-config","namespace":"default"}}`),
			GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		}},
	}, {
		name: "two-resources",
		raw: `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        backend:
          serviceName: test
          servicePort: 80
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: a-config
  namespace: default
data:
  color: "red"
  multi-line: |
    hello world
    how are you?
`,
		want: []Manifest{{
			id:  resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			Raw: []byte(`{"apiVersion":"extensions/v1beta1","kind":"Ingress","metadata":{"name":"test-ingress","namespace":"test-namespace"},"spec":{"rules":[{"http":{"paths":[{"backend":{"serviceName":"test","servicePort":80},"path":"/testpath"}]}}]}}`),
			GVK: schema.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "Ingress"},
		}, {
			id:  resourceId{Group: "", Kind: "ConfigMap", Name: "a-config", Namespace: "default"},
			Raw: []byte(`{"apiVersion":"v1","data":{"color":"red","multi-line":"hello world\nhow are you?\n"},"kind":"ConfigMap","metadata":{"name":"a-config","namespace":"default"}}`),
			GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		}},
	}, {
		name: "two-resources-with-empty",
		raw: `
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        backend:
          serviceName: test
          servicePort: 80
---
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: a-config
  namespace: default
data:
  color: "red"
  multi-line: |
    hello world
    how are you?
---
`,
		want: []Manifest{{
			id:  resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			Raw: []byte(`{"apiVersion":"extensions/v1beta1","kind":"Ingress","metadata":{"name":"test-ingress","namespace":"test-namespace"},"spec":{"rules":[{"http":{"paths":[{"backend":{"serviceName":"test","servicePort":80},"path":"/testpath"}]}}]}}`),
			GVK: schema.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "Ingress"},
		}, {
			id:  resourceId{Group: "", Kind: "ConfigMap", Name: "a-config", Namespace: "default"},
			Raw: []byte(`{"apiVersion":"v1","data":{"color":"red","multi-line":"hello world\nhow are you?\n"},"kind":"ConfigMap","metadata":{"name":"a-config","namespace":"default"}}`),
			GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		}},
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseManifests(strings.NewReader(test.raw))
			if err != nil {
				t.Fatalf("failed to parse manifest: %v", err)
			}

			for i := range got {
				got[i].Obj = nil
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("mismatch found")
			}
		})
	}

}

func TestParseManifestsDuplicates(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{{
		name: "no-duplicate",
		raw: `
apiVersion: extensions/v1
kind: ConfigMap
metadata:
  name: a-config
  namespace: default
---
apiVersion: extensions/v1
kind: ConfigMap
metadata:
  name: b-config
  namespace: default
`,
		wantErr: "",
	}, {
		name: "resource-id-error",
		raw: `
apiVersion: extensions/v1
kind: Kind
metadata:
  name:
  namespace: default
`,
		wantErr: "must contain kubernetes required fields kind and name",
	}, {
		name: "duplicate",
		raw: `
apiVersion: extensions/v1
kind: ConfigMap
metadata:
  name: a-config
  namespace: default
---
apiVersion: extensions/v2
kind: ConfigMap
metadata:
  name: a-config
  namespace: default
`,
		wantErr: "duplicate resource: (Group: \"extensions\" Kind: \"ConfigMap\" Namespace: \"default\" Name: \"a-config\")",
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseManifests(strings.NewReader(test.raw))
			if err == nil {
				if len(test.wantErr) != 0 {
					t.Fatalf("Expected an error and got none")
				}
			} else if len(test.wantErr) == 0 {
				t.Fatalf("Got unexpected error: %v", err)
			} else if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Got incorrect error. Wanted it to contain %s but got %s",
					test.wantErr, err.Error())
			}
		})
	}

}

func TestManifestsFromFiles(t *testing.T) {
	tests := []struct {
		name string
		fs   dir
		want []Manifest
	}{{
		name: "no-files",
		fs: dir{
			name: "a",
		},
		want: nil,
	}, {
		name: "all-files",
		fs: dir{
			name: "a",
			files: []file{{
				name: "f0",
				contents: `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        backend:
          serviceName: test
          servicePort: 80
`,
			}, {
				name: "f1",
				contents: `
apiVersion: v1
kind: ConfigMap
metadata:
  name: a-config
  namespace: default
data:
  color: "red"
  multi-line: |
    hello world
    how are you?
`,
			}},
		},
		want: []Manifest{{
			OriginalFilename: "f0",
			id:               resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			GVK:              schema.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "Ingress"},
		}, {
			OriginalFilename: "f1",
			id:               resourceId{Group: "", Kind: "ConfigMap", Name: "a-config", Namespace: "default"},
			GVK:              schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		}},
	}, {
		name: "files-with-multiple-manifests",
		fs: dir{
			name: "a",
			files: []file{{
				name: "f0",
				contents: `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        backend:
          serviceName: test
          servicePort: 80
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: a-config
  namespace: default
data:
  color: "red"
  multi-line: |
    hello world
    how are you?
`,
			}, {
				name: "f1",
				contents: `
apiVersion: v1
kind: ConfigMap
metadata:
  name: b-config
  namespace: default
data:
  color: "red"
  multi-line: |
    hello world
    how are you?
`,
			}},
		},
		want: []Manifest{{
			OriginalFilename: "f0",
			id:               resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			GVK:              schema.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "Ingress"},
		}, {
			OriginalFilename: "f0",
			id:               resourceId{Group: "", Kind: "ConfigMap", Name: "a-config", Namespace: "default"},
			GVK:              schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		}, {
			OriginalFilename: "f1",
			id:               resourceId{Group: "", Kind: "ConfigMap", Name: "b-config", Namespace: "default"},
			GVK:              schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		}},
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpdir, cleanup := setupTestFS(t, test.fs)
			defer func() {
				if err := cleanup(); err != nil {
					t.Logf("error cleaning %q", tmpdir)
				}
			}()

			files := []string{}
			for _, f := range test.fs.files {
				files = append(files, filepath.Join(tmpdir, test.fs.name, f.name))
			}
			got, err := ManifestsFromFiles(files)
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				t.Logf("loaded %s", &got[i])
				got[i].Raw = nil
				got[i].Obj = nil
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("mismatch \ngot: %s \nwant: %s", spew.Sdump(got), spew.Sdump(test.want))
			}
		})
	}
}

func TestManifestsFromFilesDuplicates(t *testing.T) {
	tests := []struct {
		name    string
		fs      dir
		want    []string
		wantNum int
	}{{
		name: "no-duplicates",
		fs: dir{
			name: "a",
			files: []file{{
				name: "f0",
				contents: `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
`,
			}, {
				name: "f1",
				contents: `
apiVersion: v1
kind: Ingress
metadata:
  name: test-ingress
  namespace: default
`,
			}},
		},
	}, {
		name: "duplicate",
		fs: dir{
			name: "a",
			files: []file{{
				name: "f0",
				contents: `
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
`,
			}, {
				name: "f1",
				contents: `
apiVersion: extensions/v1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
`,
			}},
		},
		want:    []string{"(Group: \"extensions\" Kind: \"Ingress\" Namespace: \"test-namespace\" Name: \"test-ingress\")"},
		wantNum: 1,
	}, {
		name: "many-duplicates",
		fs: dir{
			name: "a",
			files: []file{{
				name: "f0",
				contents: `
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm1
  namespace: test1
---
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm1
  namespace: test1
`,
			}, {
				name: "f1",
				contents: `
apiVersion: extensions/v1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
---
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm1
  namespace: test1
---
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm2
  namespace: test1
---
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm3
  namespace: test1
---
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm4
  namespace: test1
`,
			}, {
				name: "f2",
				contents: `
apiVersion: extensions/v1
kind: Ingress
metadata:
  name: test-ingress
  namespace: test-namespace
---
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm4
  namespace: test1
`,
			}, {
				name: "fs",
				contents: `
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm2
  namespace: test1
---
apiVersion: v1beta1
kind: ConfigMap
metadata:
  name: cm4
  namespace: test1
`,
			}},
		},
		want: []string{
			"(Group: \"extensions\" Kind: \"Ingress\" Namespace: \"test-namespace\" Name: \"test-ingress\")",
			"(Group: \"\" Kind: \"ConfigMap\" Namespace: \"test1\" Name: \"cm1\")",
			"(Group: \"\" Kind: \"ConfigMap\" Namespace: \"test1\" Name: \"cm2\")",
			"(Group: \"\" Kind: \"ConfigMap\" Namespace: \"test1\" Name: \"cm4\")",
		},
		wantNum: 5,
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpdir, cleanup := setupTestFS(t, test.fs)
			defer func() {
				if err := cleanup(); err != nil {
					t.Logf("error cleaning %q", tmpdir)
				}
			}()

			files := []string{}
			for _, f := range test.fs.files {
				files = append(files, filepath.Join(tmpdir, test.fs.name, f.name))
			}
			_, dupErrs := ManifestsFromFiles(files)
			if dupErrs == nil {
				if len(test.want) != 0 {
					t.Fatalf("Expected duplicate errors and got none")
				}
			} else {
				dupCount := strings.Count(dupErrs.Error(), "Group:")
				if test.wantNum != dupCount {
					t.Fatalf("Expected %d duplicates but got %d. Duplicates error:\n%s",
						test.wantNum, dupCount, dupErrs.Error())
				}
				for _, s := range test.want {
					if !strings.Contains(dupErrs.Error(), s) ||
						!strings.Contains(dupErrs.Error(), "duplicate resource:") {
						t.Fatalf("Missing error for duplicate resource: %s", s)
					}
				}
			}
		})
	}
}

type file struct {
	name     string
	contents string
}

type dir struct {
	name  string
	files []file
}

// setupTestFS returns path of the tmp d created and cleanup function.
func setupTestFS(t *testing.T, d dir) (string, func() error) {
	root, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	dpath := filepath.Join(root, d.name)
	if err := os.MkdirAll(dpath, 0755); err != nil {
		t.Fatal(err)
	}
	for _, file := range d.files {
		path := filepath.Join(dpath, file.name)
		os.WriteFile(path, []byte(file.contents), 0755)
	}
	cleanup := func() error {
		return os.RemoveAll(root)
	}
	return root, cleanup
}

func Test_include(t *testing.T) {
	identifier := "identifier"
	defaultClusterProfile := "self-managed-high-availability"
	singleNodeProfile := "single-node"

	tests := []struct {
		name                string
		exclude             *string
		requiredFeatureSet  *string
		profile             *string
		annotations         map[string]interface{}
		caps                *configv1.ClusterVersionCapabilitiesStatus
		overrides           []configv1.ComponentOverride
		enabledFeatureGates sets.Set[string]

		expected error
	}{
		{
			name:    "exclusion identifier set",
			exclude: &identifier,
			profile: &defaultClusterProfile,
			annotations: map[string]interface{}{
				"exclude.release.openshift.io/identifier":                     "true",
				"include.release.openshift.io/self-managed-high-availability": "true"},
			expected: fmt.Errorf("exclude.release.openshift.io/identifier=true"),
		},
		{
			name:    "exclusion identifier set with no capability",
			exclude: &identifier,
			profile: &defaultClusterProfile,
			annotations: map[string]interface{}{
				"exclude.release.openshift.io/identifier":                     "true",
				"include.release.openshift.io/self-managed-high-availability": "true"},
			caps:     &configv1.ClusterVersionCapabilitiesStatus{},
			expected: fmt.Errorf("exclude.release.openshift.io/identifier=true"),
		},
		{
			name:        "profile selection works",
			profile:     &singleNodeProfile,
			annotations: map[string]interface{}{"include.release.openshift.io/self-managed-high-availability": "true"},
			expected:    fmt.Errorf("include.release.openshift.io/single-node unset"),
		},
		{
			name:        "No profile",
			profile:     nil,
			annotations: map[string]interface{}{"include.release.openshift.io/self-managed-high-availability": "true"},
			expected:    nil,
		},
		{
			name:        "profile selection works included",
			profile:     &defaultClusterProfile,
			annotations: map[string]interface{}{"include.release.openshift.io/self-managed-high-availability": "true"},
		},
		{
			name:               "unspecified manifest included if techpreview off",
			requiredFeatureSet: ptr.To(""),
			profile:            &defaultClusterProfile,
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
			},
		},
		{
			name:               "unspecified manifest included if techpreview on",
			requiredFeatureSet: ptr.To("TechPreviewNoUpgrade"),
			profile:            &defaultClusterProfile,
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
			},
		},
		{
			name:               "correct techpreview value is excluded if techpreview off using feature-set",
			requiredFeatureSet: ptr.To(""),
			profile:            &defaultClusterProfile,
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				"release.openshift.io/feature-set":                            "TechPreviewNoUpgrade",
			},
			expected: fmt.Errorf("\"Default\" is required, and release.openshift.io/feature-set=TechPreviewNoUpgrade"),
		},
		{
			name:               "correct techpreview value is included if techpreview on using feature-set",
			requiredFeatureSet: ptr.To("TechPreviewNoUpgrade"),
			profile:            &defaultClusterProfile,
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				"release.openshift.io/feature-set":                            "TechPreviewNoUpgrade",
			},
		},
		{
			name:               "incorrect techpreview value is not excluded if techpreview off using feature-set",
			requiredFeatureSet: ptr.To(""),
			profile:            &defaultClusterProfile,
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				"release.openshift.io/feature-set":                            "Other",
			},
			expected: fmt.Errorf("unrecognized value \"Other\" in release.openshift.io/feature-set=Other; known values are: CustomNoUpgrade,Default,DevPreviewNoUpgrade,OKD,TechPreviewNoUpgrade"),
		},
		{
			name:               "incorrect techpreview value is not excluded if techpreview on using feature-set",
			requiredFeatureSet: ptr.To("TechPreviewNoUpgrade"),
			profile:            &defaultClusterProfile,
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				"release.openshift.io/feature-set":                            "Other",
			},
			expected: fmt.Errorf("unrecognized value \"Other\" in release.openshift.io/feature-set=Other; known values are: CustomNoUpgrade,Default,DevPreviewNoUpgrade,OKD,TechPreviewNoUpgrade"),
		},
		{
			name:        "default profile selection excludes without annotation",
			profile:     &defaultClusterProfile,
			annotations: map[string]interface{}{},
			expected:    fmt.Errorf("include.release.openshift.io/self-managed-high-availability unset"),
		},
		{
			name:        "default profile selection excludes with no annotation",
			profile:     &defaultClusterProfile,
			annotations: nil,
			expected:    fmt.Errorf("no annotations"),
		},
		{
			name: "unrecognized capability annotaton",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1"},
			expected: nil,
		},
		{
			name: "disabled capability",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1"},
			caps: &configv1.ClusterVersionCapabilitiesStatus{
				KnownCapabilities: []configv1.ClusterVersionCapability{"cap1"},
			},
			expected: fmt.Errorf("disabled capabilities: cap1"),
		},
		{
			name: "enabled capability",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1"},
			caps: &configv1.ClusterVersionCapabilitiesStatus{
				KnownCapabilities:   []configv1.ClusterVersionCapability{"cap1"},
				EnabledCapabilities: []configv1.ClusterVersionCapability{"cap1"},
			},
		},
		{
			name: "multiple capabilities, 1 unknown",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1+cap2"},
			caps: &configv1.ClusterVersionCapabilitiesStatus{
				KnownCapabilities:   []configv1.ClusterVersionCapability{"cap1", "cap3"},
				EnabledCapabilities: []configv1.ClusterVersionCapability{"cap1", "cap3"},
			},
			expected: fmt.Errorf("unrecognized capability names: cap2"),
		},
		{
			name: "multiple capabilities, 1 disabled",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1+cap2"},
			caps: &configv1.ClusterVersionCapabilitiesStatus{
				KnownCapabilities:   []configv1.ClusterVersionCapability{"cap1", "cap2", "cap3"},
				EnabledCapabilities: []configv1.ClusterVersionCapability{"cap1", "cap3"},
			},
			expected: fmt.Errorf("disabled capabilities: cap2"),
		},
		{
			name: "multiple capabilities, all enabled",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1+cap2+cap3"},
			caps: &configv1.ClusterVersionCapabilitiesStatus{
				KnownCapabilities:   []configv1.ClusterVersionCapability{"cap1", "cap2", "cap3"},
				EnabledCapabilities: []configv1.ClusterVersionCapability{"cap1", "cap2", "cap3"},
			},
		},
		{
			name:        "unrelated override",
			annotations: map[string]interface{}{},
			overrides: []configv1.ComponentOverride{
				{
					Kind:      "Pod",
					Name:      "my-pod",
					Namespace: "my-namespace",
					Unmanaged: true,
				},
			},
		},
		{
			name:        "override, but managed",
			annotations: map[string]interface{}{},
			overrides: []configv1.ComponentOverride{
				{
					Group:     "apps",
					Kind:      "Deployment",
					Name:      "my-deployment",
					Namespace: "my-namespace",
				},
			},
		},
		{
			name:        "unmanaged override",
			annotations: map[string]interface{}{},
			overrides: []configv1.ComponentOverride{
				{
					Group:     "apps",
					Kind:      "Deployment",
					Name:      "my-deployment",
					Namespace: "my-namespace",
					Unmanaged: true,
				},
			},
			expected: fmt.Errorf("overridden"),
		},
		{
			name:                "feature gate required but not enabled",
			enabledFeatureGates: sets.New("FeatureGate1"),
			annotations: map[string]interface{}{
				"release.openshift.io/feature-gate": "FeatureGate2",
			},
			expected: fmt.Errorf("feature gate FeatureGate2 is required but not enabled"),
		},
		{
			name:                "feature gate enabled but manifest requires it to be disabled",
			enabledFeatureGates: sets.New("FeatureGate1"),
			annotations: map[string]interface{}{
				"release.openshift.io/feature-gate": "-FeatureGate1",
			},
			expected: fmt.Errorf("feature gate FeatureGate1 is enabled but manifest requires it to be disabled"),
		},
		{
			name:                "feature gate required and is enabled",
			enabledFeatureGates: sets.New("FeatureGate1"),
			annotations: map[string]interface{}{
				"release.openshift.io/feature-gate": "FeatureGate1",
			},
		},
		{
			name:                "feature set required and feature gate specified",
			requiredFeatureSet:  ptr.To("FeatureSet1"),
			enabledFeatureGates: sets.New("FeatureGate1"),
			annotations: map[string]interface{}{
				"release.openshift.io/feature-set":  "FeatureSet1",
				"release.openshift.io/feature-gate": "FeatureGate1",
			},
			expected: fmt.Errorf("both feature set and feature gate annotations are present: manifests may specify either a feature set or a feature gate, but not both"),
		},
		{
			name:        "all nil",
			profile:     nil,
			annotations: nil,
			expected:    fmt.Errorf("no annotations"),
		},
	}

	for _, tt := range tests {
		metadata := map[string]interface{}{
			"name":      "my-deployment",
			"namespace": "my-namespace",
		}
		t.Run(tt.name, func(t *testing.T) {
			if tt.annotations != nil {
				metadata["annotations"] = tt.annotations
			}
			m := Manifest{
				Obj: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "apps/v1",
						"kind":       "Deployment",
						"metadata":   metadata,
					},
				},
			}
			err := m.populateFromObj()
			assert.Equal(t, nil, err)

			err = m.Include(tt.exclude, tt.requiredFeatureSet, tt.profile, tt.caps, tt.overrides, tt.enabledFeatureGates)
			assert.Equal(t, tt.expected, err)
		})
	}
}

func TestIncludeAllowUnknownCapabilities(t *testing.T) {

	tests := []struct {
		name                string
		exclude             *string
		requiredFeatureSet  *string
		profile             *string
		annotations         map[string]interface{}
		caps                *configv1.ClusterVersionCapabilitiesStatus
		overrides           []configv1.ComponentOverride
		enabledFeatureGates sets.Set[string]
		allowUnknown        bool

		expected error
	}{
		{
			name: "multiple capabilities, 1 unknown",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1+cap2"},
			caps: &configv1.ClusterVersionCapabilitiesStatus{
				KnownCapabilities:   []configv1.ClusterVersionCapability{"cap1", "cap3"},
				EnabledCapabilities: []configv1.ClusterVersionCapability{"cap1", "cap3"},
			},
			allowUnknown: false,
			expected:     fmt.Errorf("unrecognized capability names: cap2"),
		},
		{
			name: "unknown allowed",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1+cap2"},
			caps: &configv1.ClusterVersionCapabilitiesStatus{
				KnownCapabilities:   []configv1.ClusterVersionCapability{"cap1", "cap3"},
				EnabledCapabilities: []configv1.ClusterVersionCapability{"cap1", "cap3"},
			},
			allowUnknown: true,
			expected:     fmt.Errorf("disabled capabilities: cap2"),
		},
	}

	for _, tt := range tests {
		metadata := map[string]interface{}{}
		t.Run(tt.name, func(t *testing.T) {
			if tt.annotations != nil {
				metadata["annotations"] = tt.annotations
			}
			m := Manifest{
				Obj: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"metadata": metadata,
					},
				},
			}
			err := m.IncludeAllowUnknownCapabilities(tt.exclude, tt.requiredFeatureSet, tt.profile, tt.caps, tt.overrides, tt.enabledFeatureGates, tt.allowUnknown)
			assert.Equal(t, tt.expected, err)
		})
	}
}

func TestGetManifestCapabilities(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]interface{}
		want        []configv1.ClusterVersionCapability
	}{
		{
			name: "no annotations",
		},
		{
			name: "no capability annotation",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
			},
		},
		{
			name: "empty capabilities annotation",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: ""},
		},
		{
			name: "capabilities",
			annotations: map[string]interface{}{
				"include.release.openshift.io/self-managed-high-availability": "true",
				CapabilityAnnotation: "cap1+cap2"},
			want: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap1"),
				configv1.ClusterVersionCapability("cap2"),
			},
		},
	}
	for _, tt := range tests {
		metadata := map[string]interface{}{}
		t.Run(tt.name, func(t *testing.T) {
			if tt.annotations != nil {
				metadata["annotations"] = tt.annotations
			}
			m := Manifest{
				Obj: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"metadata": metadata,
					},
				},
			}
			caps := m.GetManifestCapabilities()
			assert.Equal(t, tt.want, caps)
		})
	}
}

func TestSameResourceID(t *testing.T) {
	tests := []struct {
		name    string
		id      resourceId
		otherId resourceId
		want    bool
	}{
		{
			name:    "same id",
			id:      resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			otherId: resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			want:    true,
		},
		{
			name: "default id",
			id:   resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			want: false,
		},
		{
			name:    "different Group",
			id:      resourceId{Group: "extensionsA", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			otherId: resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			want:    false,
		},
		{
			name:    "different Kind",
			id:      resourceId{Group: "extensions", Kind: "IngressA", Name: "test-ingress", Namespace: "test-namespace"},
			otherId: resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			want:    false,
		},
		{
			name:    "different Name",
			id:      resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingressA", Namespace: "test-namespace"},
			otherId: resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			want:    false,
		},
		{
			name:    "different Namespace",
			id:      resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespaceA"},
			otherId: resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			man := Manifest{
				id: tt.id,
			}
			otherMan := Manifest{
				id: tt.otherId,
			}
			assert.Equal(t, tt.want, man.SameResourceID(otherMan))
		})
	}
}

func TestCheckFeatureGates(t *testing.T) {
	tests := []struct {
		name         string
		enabledGates sets.Set[string]
		annotations  map[string]string
		expectedErr  string
	}{
		{
			name:         "no feature gate annotation",
			enabledGates: sets.New("gate1", "gate2"),
			annotations:  map[string]string{},
			expectedErr:  "",
		},
		{
			name:         "empty feature gate annotation",
			enabledGates: sets.New("gate1", "gate2"),
			annotations:  map[string]string{featureGateAnnotation: ""},
			expectedErr:  "",
		},
		{
			name:         "required gate is enabled - should include",
			enabledGates: sets.New("TechPreviewFeatureGate", "gate2"),
			annotations:  map[string]string{featureGateAnnotation: "TechPreviewFeatureGate"},
			expectedErr:  "",
		},
		{
			name:         "required gate is not enabled - should exclude",
			enabledGates: sets.New("gate1", "gate2"),
			annotations:  map[string]string{featureGateAnnotation: "TechPreviewFeatureGate"},
			expectedErr:  "feature gate TechPreviewFeatureGate is required but not enabled",
		},
		{
			name:         "excluded gate is not enabled - should include",
			enabledGates: sets.New("gate1", "gate2"),
			annotations:  map[string]string{featureGateAnnotation: "-TechPreviewFeatureGate"},
			expectedErr:  "",
		},
		{
			name:         "excluded gate is enabled - should exclude",
			enabledGates: sets.New("TechPreviewFeatureGate", "gate2"),
			annotations:  map[string]string{featureGateAnnotation: "-TechPreviewFeatureGate"},
			expectedErr:  "feature gate TechPreviewFeatureGate is enabled but manifest requires it to be disabled",
		},
		{
			name:         "multiple requirements - all satisfied",
			enabledGates: sets.New("gate1", "gate2"),
			annotations:  map[string]string{featureGateAnnotation: "gate1,gate2,-gate3"},
			expectedErr:  "",
		},
		{
			name:         "multiple requirements - inclusion not satisfied",
			enabledGates: sets.New("gate1"),
			annotations:  map[string]string{featureGateAnnotation: "gate1,gate2,-gate3"},
			expectedErr:  "feature gate gate2 is required but not enabled",
		},
		{
			name:         "multiple requirements - exclusion not satisfied",
			enabledGates: sets.New("gate1", "gate2", "gate3"),
			annotations:  map[string]string{featureGateAnnotation: "gate1,gate2,-gate3"},
			expectedErr:  "feature gate gate3 is enabled but manifest requires it to be disabled",
		},
		{
			name:         "whitespace handling",
			enabledGates: sets.New("gate1", "gate2"),
			annotations:  map[string]string{featureGateAnnotation: " gate1 , gate2 , -gate3 "},
			expectedErr:  "",
		},
		{
			name:         "empty requirements in list",
			enabledGates: sets.New("gate1"),
			annotations:  map[string]string{featureGateAnnotation: "gate1,,"},
			expectedErr:  "",
		},
		{
			name:         "complex scenario - OR logic for inclusion",
			enabledGates: sets.New("NewStorageFeature"),
			annotations:  map[string]string{featureGateAnnotation: "NewStorageFeature,AlternativeStorageFeature"},
			expectedErr:  "feature gate AlternativeStorageFeature is required but not enabled",
		},
		{
			name:         "complex scenario - AND logic for mixed requirements",
			enabledGates: sets.New("FeatureA"),
			annotations:  map[string]string{featureGateAnnotation: "FeatureA,-FeatureB"},
			expectedErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkFeatureGates(tt.enabledGates, tt.annotations)
			if tt.expectedErr == "" {
				if err != nil {
					t.Errorf("checkFeatureGates() expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("checkFeatureGates() expected error %q, got nil", tt.expectedErr)
				} else if err.Error() != tt.expectedErr {
					t.Errorf("checkFeatureGates() expected error %q, got %q", tt.expectedErr, err.Error())
				}
			}
		})
	}
}

func TestManifestIncludeWithFeatureGates(t *testing.T) {
	// Test just the feature gate functionality by testing manifest with no other filtering requirements
	tests := []struct {
		name         string
		enabledGates sets.Set[string]
		annotations  map[string]interface{}
		expectedErr  string
	}{
		{
			name:         "manifest included when feature gate enabled",
			enabledGates: sets.New("TechPreviewFeatureGate"),
			annotations: map[string]interface{}{
				featureGateAnnotation: "TechPreviewFeatureGate",
			},
			expectedErr: "",
		},
		{
			name:         "manifest excluded when feature gate disabled",
			enabledGates: sets.New("SomeOtherGate"),
			annotations: map[string]interface{}{
				featureGateAnnotation: "TechPreviewFeatureGate",
			},
			expectedErr: "feature gate TechPreviewFeatureGate is required but not enabled",
		},
	}

	for _, tt := range tests {
		metadata := map[string]interface{}{
			"name":      "test",
			"namespace": "test",
		}

		t.Run(tt.name, func(t *testing.T) {
			if tt.annotations != nil {
				metadata["annotations"] = tt.annotations
			}
			manifest := Manifest{
				Obj: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"metadata": metadata,
					},
				},
			}

			// Test only feature gates, set all other filters to nil
			err := manifest.Include(nil, nil, nil, nil, nil, tt.enabledGates)
			if tt.expectedErr == "" {
				if err != nil {
					t.Errorf("manifest.Include() expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("manifest.Include() expected error containing %q, got nil", tt.expectedErr)
				} else if !strings.Contains(err.Error(), tt.expectedErr) {
					t.Errorf("manifest.Include() expected error containing %q, got %q", tt.expectedErr, err.Error())
				}
			}
		})
	}
}
