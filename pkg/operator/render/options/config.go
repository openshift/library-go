package options

import (
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/klog/v2"
)

// ManifestConfig is a struct of values to be used in manifest templates.
type ManifestConfig struct {
	// ConfigHostPath is a host path mounted into the controller manager pods to hold the config file.
	ConfigHostPath string

	// ConfigFileName is the filename of config file inside ConfigHostPath.
	ConfigFileName string

	// CloudProviderHostPath is a host path mounted into the apiserver pods to hold cloud provider configuration.
	CloudProviderHostPath string

	// SecretsHostPath holds certs and keys
	SecretsHostPath string

	// Namespace is the target namespace for the bootstrap controller manager to be created.
	Namespace string

	// Image is the pull spec of the image to use for the controller manager.
	Image string

	// OperatorImage is the pull spec of the image to use for the operator (optional).
	OperatorImage string

	// ImagePullPolicy specifies the image pull policy to use for the images.
	ImagePullPolicy string
}

type FileConfig struct {
	// BootstrapConfig holds the rendered control plane component config file for bootstrapping (phase 1).
	BootstrapConfig []byte

	// Assets holds the loaded assets like certs and keys.
	Assets map[string][]byte
}

type RenderedManifests []RenderedManifest

type RenderedManifest struct {
	OriginalFilename string
	Content          []byte

	// use GetDecodedObj to access
	decodedObj runtime.Object
}

type TemplateData struct {
	ManifestConfig
	FileConfig
}

func (c RenderedManifests) ListManifestOfType(gvk schema.GroupVersionKind) []RenderedManifest {
	ret := []RenderedManifest{}
	for i := range c {
		obj, err := c[i].GetDecodedObj()
		if err != nil {
			klog.Warningf("failure to read %q: %v", c[i].OriginalFilename, err)
			continue
		}
		if obj.GetObjectKind().GroupVersionKind() == gvk {
			ret = append(ret, c[i])
		}
	}

	return ret
}

func (c *RenderedManifest) GetDecodedObj() (runtime.Object, error) {
	if c.decodedObj != nil {
		return c.decodedObj, nil
	}
	obj, err := resourceread.ReadGenericWithUnstructured(c.Content)
	if err != nil {
		return nil, err
	}
	c.decodedObj = obj

	return c.decodedObj, nil
}
