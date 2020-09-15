// Code generated for package bindata by go-bindata DO NOT EDIT. (@generated)
// sources:
// pkg/operator/apiserver/audit/manifests/audit-policies-cm.yaml
package bindata

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _pkgOperatorApiserverAuditManifestsAuditPoliciesCmYaml = []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: ${TARGET_NAME}
  namespace: ${TARGET_NAMESPACE}
data:
  default.yaml: |
    apiVersion: audit.k8s.io/v1beta1
    kind: Policy
    metadata:
      name: Default
    # Don't generate audit events for all requests in RequestReceived stage.
    omitStages:
    - "RequestReceived"
    rules:
    # Don't log requests for events
    - level: None
      resources:
      - group: ""
        resources: ["events"]
    # Don't log oauth tokens as metadata.name is the secret
    - level: None
      resources:
      - group: "oauth.openshift.io"
        resources: ["oauthaccesstokens", "oauthauthorizetokens"]
    # Don't log authenticated requests to certain non-resource URL paths.
    - level: None
      userGroups: ["system:authenticated", "system:unauthenticated"]
      nonResourceURLs:
      - "/api*" # Wildcard matching.
      - "/version"
      - "/healthz"
      - "/readyz"
    # Log the full Identity API resource object so that the audit trail
    # allows us to match the username with the IDP identity.
    - level: RequestResponse
      verbs: ["create", "update", "patch"]
      resources:
        - group: "user.openshift.io"
          resources: ["identities"]
    # A catch-all rule to log all other requests at the Metadata level.
    - level: Metadata
      # Long-running requests like watches that fall under this rule will not
      # generate an audit event in RequestReceived.
      omitStages:
      - "RequestReceived"

  writerequestbodies.yaml: |
    apiVersion: audit.k8s.io/v1beta1
    kind: Policy
    metadata:
      name: WriteRequestBodies
    # Don't generate audit events for all requests in RequestReceived stage.
    omitStages:
    - "RequestReceived"
    rules:
    # Don't log requests for events
    - level: None
      resources:
      - group: ""
        resources: ["events"]
    # Don't log oauth tokens as metadata.name is the secret
    - level: None
      resources:
      - group: "oauth.openshift.io"
        resources: ["oauthaccesstokens", "oauthauthorizetokens"]
    # Don't log authenticated requests to certain non-resource URL paths.
    - level: None
      userGroups: ["system:authenticated", "system:unauthenticated"]
      nonResourceURLs:
      - "/api*" # Wildcard matching.
      - "/version"
      - "/healthz"
      - "/readyz"
    # exclude resources where the body is security-sensitive
    - level: Metadata
      resources:
      - group: "route.openshift.io"
        resources: ["routes"]
      - resources: ["secrets"]
    - level: Metadata
      resources:
      - group: "oauth.openshift.io"
        resources: ["oauthclients"]
    # log request and response payloads for all write requests
    - level: RequestResponse
      verbs:
      - update
      - patch
      - create
      - delete
      - deletecollection
    # catch-all rule to log all other requests at the Metadata level.
    - level: Metadata
      # Long-running requests like watches that fall under this rule will not
      # generate an audit event in RequestReceived.
      omitStages:
      - RequestReceived

  allrequestbodies.yaml: |
    apiVersion: audit.k8s.io/v1beta1
    kind: Policy
    metadata:
      name: AllRequestBodies
    # Don't generate audit events for all requests in RequestReceived stage.
    omitStages:
    - "RequestReceived"
    rules:
    # Don't log requests for events
    - level: None
      resources:
      - group: ""
        resources: ["events"]
    # Don't log oauth tokens as metadata.name is the secret
    - level: None
      resources:
      - group: "oauth.openshift.io"
        resources: ["oauthaccesstokens", "oauthauthorizetokens"]
    # Don't log authenticated requests to certain non-resource URL paths.
    - level: None
      userGroups: ["system:authenticated", "system:unauthenticated"]
      nonResourceURLs:
      - "/api*" # Wildcard matching.
      - "/version"
      - "/healthz"
      - "/readyz"
    # exclude resources where the body is security-sensitive
    - level: Metadata
      resources:
      - group: "route.openshift.io"
        resources: ["routes"]
      - resources: ["secrets"]
    - level: Metadata
      resources:
      - group: "oauth.openshift.io"
        resources: ["oauthclients"]
    # catch-all rule to log all other requests with request and response payloads
    - level: RequestResponse

  secure-oauth-storage-default.yaml: |
    apiVersion: audit.k8s.io/v1beta1
    kind: Policy
    metadata:
      name: Default
    # Don't generate audit events for all requests in RequestReceived stage.
    omitStages:
    - "RequestReceived"
    rules:
    # Don't log requests for events
    - level: None
      resources:
      - group: ""
        resources: ["events"]
    # Don't log authenticated requests to certain non-resource URL paths.
    - level: None
      userGroups: ["system:authenticated", "system:unauthenticated"]
      nonResourceURLs:
      - "/api*" # Wildcard matching.
      - "/version"
      - "/healthz"
      - "/readyz"
    # Log the full Identity API resource object so that the audit trail
    # allows us to match the username with the IDP identity.
    - level: RequestResponse
      verbs: ["create", "update", "patch"]
      resources:
        - group: "user.openshift.io"
          resources: ["identities"]
        - group: "oauth.openshift.io"
          resources: ["oauthaccesstokens", "oauthauthorizetokens"]
    # A catch-all rule to log all other requests at the Metadata level.
    - level: Metadata
      # Long-running requests like watches that fall under this rule will not
      # generate an audit event in RequestReceived.
      omitStages:
      - "RequestReceived"

  secure-oauth-storage-writerequestbodies.yaml: |
    apiVersion: audit.k8s.io/v1beta1
    kind: Policy
    metadata:
      name: WriteRequestBodies
    # Don't generate audit events for all requests in RequestReceived stage.
    omitStages:
    - "RequestReceived"
    rules:
    # Don't log requests for events
    - level: None
      resources:
      - group: ""
        resources: ["events"]
    # Don't log authenticated requests to certain non-resource URL paths.
    - level: None
      userGroups: ["system:authenticated", "system:unauthenticated"]
      nonResourceURLs:
      - "/api*" # Wildcard matching.
      - "/version"
      - "/healthz"
      - "/readyz"
    # exclude resources where the body is security-sensitive
    - level: Metadata
      resources:
      - group: "route.openshift.io"
        resources: ["routes"]
      - resources: ["secrets"]
    - level: Metadata
      resources:
      - group: "oauth.openshift.io"
        resources: ["oauthclients"]
    # log request and response payloads for all write requests
    - level: RequestResponse
      verbs:
      - update
      - patch
      - create
      - delete
      - deletecollection
    # catch-all rule to log all other requests at the Metadata level.
    - level: Metadata
      # Long-running requests like watches that fall under this rule will not
      # generate an audit event in RequestReceived.
      omitStages:
      - RequestReceived

  secure-oauth-storage-allrequestbodies.yaml: |
    apiVersion: audit.k8s.io/v1beta1
    kind: Policy
    metadata:
      name: AllRequestBodies
    # Don't generate audit events for all requests in RequestReceived stage.
    omitStages:
    - "RequestReceived"
    rules:
    # Don't log requests for events
    - level: None
      resources:
      - group: ""
        resources: ["events"]
    # Don't log authenticated requests to certain non-resource URL paths.
    - level: None
      userGroups: ["system:authenticated", "system:unauthenticated"]
      nonResourceURLs:
      - "/api*" # Wildcard matching.
      - "/version"
      - "/healthz"
      - "/readyz"
    # exclude resources where the body is security-sensitive
    - level: Metadata
      resources:
      - group: "route.openshift.io"
        resources: ["routes"]
      - resources: ["secrets"]
    - level: Metadata
      resources:
      - group: "oauth.openshift.io"
        resources: ["oauthclients"]
    # catch-all rule to log all other requests with request and response payloads
    - level: RequestResponse`)

func pkgOperatorApiserverAuditManifestsAuditPoliciesCmYamlBytes() ([]byte, error) {
	return _pkgOperatorApiserverAuditManifestsAuditPoliciesCmYaml, nil
}

func pkgOperatorApiserverAuditManifestsAuditPoliciesCmYaml() (*asset, error) {
	bytes, err := pkgOperatorApiserverAuditManifestsAuditPoliciesCmYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "pkg/operator/apiserver/audit/manifests/audit-policies-cm.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"pkg/operator/apiserver/audit/manifests/audit-policies-cm.yaml": pkgOperatorApiserverAuditManifestsAuditPoliciesCmYaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"pkg": {nil, map[string]*bintree{
		"operator": {nil, map[string]*bintree{
			"apiserver": {nil, map[string]*bintree{
				"audit": {nil, map[string]*bintree{
					"manifests": {nil, map[string]*bintree{
						"audit-policies-cm.yaml": {pkgOperatorApiserverAuditManifestsAuditPoliciesCmYaml, map[string]*bintree{}},
					}},
				}},
			}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
