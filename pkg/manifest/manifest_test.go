package manifest

import (
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
			id:  resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			GVK: schema.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "Ingress"},
		}, {
			id:  resourceId{Group: "", Kind: "ConfigMap", Name: "a-config", Namespace: "default"},
			GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
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
			id:  resourceId{Group: "extensions", Kind: "Ingress", Name: "test-ingress", Namespace: "test-namespace"},
			GVK: schema.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "Ingress"},
		}, {
			id:  resourceId{Group: "", Kind: "ConfigMap", Name: "a-config", Namespace: "default"},
			GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		}, {
			id:  resourceId{Group: "", Kind: "ConfigMap", Name: "b-config", Namespace: "default"},
			GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
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
	root, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Fatal(err)
	}
	dpath := filepath.Join(root, d.name)
	if err := os.MkdirAll(dpath, 0755); err != nil {
		t.Fatal(err)
	}
	for _, file := range d.files {
		path := filepath.Join(dpath, file.name)
		ioutil.WriteFile(path, []byte(file.contents), 0755)
	}
	cleanup := func() error {
		return os.RemoveAll(root)
	}
	return root, cleanup
}
