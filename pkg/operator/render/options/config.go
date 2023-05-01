package options

import (
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"k8s.io/apimachinery/pkg/api/equality"
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

func (renderedManifests RenderedManifests) ListManifestOfType(gvk schema.GroupVersionKind) []RenderedManifest {
	ret := []RenderedManifest{}
	for i := range renderedManifests {
		obj, err := renderedManifests[i].GetDecodedObj()
		if err != nil {
			klog.Warningf("failure to read %q: %v", renderedManifests[i].OriginalFilename, err)
			continue
		}
		if obj.GetObjectKind().GroupVersionKind() == gvk {
			ret = append(ret, renderedManifests[i])
		}
	}

	return ret
}

func (renderedManifests RenderedManifests) GetManifest(gvk schema.GroupVersionKind, namespace, name string) (RenderedManifest, error) {
	for i := range renderedManifests {
		obj, err := renderedManifests[i].GetDecodedObj()
		if err != nil {
			klog.Warningf("failure to read %q: %v", renderedManifests[i].OriginalFilename, err)
			continue
		}
		if obj.GetObjectKind().GroupVersionKind() != gvk {
			continue
		}
		objMetadata, err := meta.Accessor(obj)
		if err != nil {
			klog.Warningf("failure to read metadata %q: %v", renderedManifests[i].OriginalFilename, err)
			continue
		}

		// since validation requires that all of these are the same, it doesn't matterwhich one we return
		if objMetadata.GetName() == name && objMetadata.GetNamespace() == namespace {
			return renderedManifests[i], nil
		}
	}

	return RenderedManifest{}, apierrors.NewNotFound(
		schema.GroupResource{
			Group:    gvk.Group,
			Resource: gvk.Kind,
		},
		name)
}

func (renderedManifests RenderedManifests) GetObject(gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error) {
	manifest, err := renderedManifests.GetManifest(gvk, namespace, name)
	if err != nil {
		return nil, err
	}
	return manifest.decodedObj, nil
}

func (renderedManifests RenderedManifests) ValidateManifestPredictability() error {
	errs := []error{}
	decodeErrorsObserved := map[int]bool{}
	metadataErrorsObserved := map[int]bool{}

	type compareTuple struct {
		i, j int
	}
	compareTuplesErrorsObserved := map[compareTuple]bool{}

	for i := range renderedManifests {
		lhs := renderedManifests[i]
		lhsObj, err := lhs.GetDecodedObj()
		if err != nil {
			if !decodeErrorsObserved[i] {
				errs = append(errs, err)
				decodeErrorsObserved[i] = true
			}
			continue
		}
		lhsMetadata, err := meta.Accessor(lhsObj)
		if err != nil {
			if !metadataErrorsObserved[i] {
				errs = append(errs, fmt.Errorf("unable to read metadata for %q: %w", lhs.OriginalFilename, err))
				metadataErrorsObserved[i] = true
			}
			continue
		}

		for j := range renderedManifests {
			if i == j {
				continue
			}
			rhs := renderedManifests[j]
			rhsObj, err := rhs.GetDecodedObj()
			if err != nil {
				if !decodeErrorsObserved[j] {
					errs = append(errs, err)
					decodeErrorsObserved[j] = true
				}
				continue
			}
			rhsMetadata, err := meta.Accessor(rhsObj)
			if err != nil {
				if !metadataErrorsObserved[j] {
					errs = append(errs, fmt.Errorf("unable to read metadata for %q: %w", rhs.OriginalFilename, err))
					metadataErrorsObserved[j] = true
				}
				continue
			}
			if lhsObj.GetObjectKind().GroupVersionKind().GroupKind() != rhsObj.GetObjectKind().GroupVersionKind().GroupKind() {
				continue
			}
			if lhsMetadata.GetName() != rhsMetadata.GetName() {
				continue
			}
			if lhsMetadata.GetNamespace() != rhsMetadata.GetNamespace() {
				continue
			}

			if !equality.Semantic.DeepEqual(lhsObj, rhsObj) {
				if !compareTuplesErrorsObserved[compareTuple{i, j}] {
					errs = append(errs,
						fmt.Errorf("%q and %q both set %v.%v/%v in ns/%v, but have different values",
							lhs.OriginalFilename,
							rhs.OriginalFilename,
							lhsObj.GetObjectKind().GroupVersionKind().Kind,
							lhsObj.GetObjectKind().GroupVersionKind().Group,
							lhsMetadata.GetName(),
							lhsMetadata.GetNamespace(),
						))
					compareTuplesErrorsObserved[compareTuple{i, j}] = true
					compareTuplesErrorsObserved[compareTuple{j, i}] = true
				}
			}
		}
	}

	return utilerrors.NewAggregate(errs)
}

func (c *RenderedManifest) GetDecodedObj() (runtime.Object, error) {
	if c.decodedObj != nil {
		return c.decodedObj, nil
	}
	obj, err := resourceread.ReadGenericWithUnstructured(c.Content)
	if err != nil {
		return nil, fmt.Errorf("unable to decode %q: %w", c.OriginalFilename, err)
	}
	c.decodedObj = obj

	return c.decodedObj, nil
}
