package encoding

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

var internalKMSPluginConfigGV = schema.GroupVersion{Group: "encryption.operator.openshift.io", Version: "v1"}

// internalKMSPluginConfigEnvelope is an envelope type used to serialize
// InternalKMSPluginConfig through the Kubernetes codec infrastructure.
type internalKMSPluginConfigEnvelope struct {
	metav1.TypeMeta `json:",inline"`
	Plugin          configv1.KMSPluginConfig `json:"plugin"`
	KMSPluginImage  string                   `json:"kmsPluginImage,omitempty"`
}

func (e *internalKMSPluginConfigEnvelope) DeepCopyObject() runtime.Object {
	out := new(internalKMSPluginConfigEnvelope)
	*out = *e
	out.Plugin = *e.Plugin.DeepCopy()
	return out
}

var (
	scheme         = runtime.NewScheme()
	codecs         = serializer.NewCodecFactory(scheme)
	jsonSerializer runtime.Serializer
)

func init() {
	utilruntime.Must(configv1.AddToScheme(scheme))
	utilruntime.Must(apiserverconfigv1.AddToScheme(scheme))
	scheme.AddKnownTypes(internalKMSPluginConfigGV, &internalKMSPluginConfigEnvelope{})
	metav1.AddToGroupVersion(scheme, internalKMSPluginConfigGV)
	codecs = serializer.NewCodecFactory(scheme)
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), runtime.ContentTypeJSON)
	if !ok {
		panic("json is not a supported media type")
	}
	jsonSerializer = info.Serializer
}

// EncodeEncryptionConfiguration serializes an EncryptionConfiguration to its serialized representation.
func EncodeEncryptionConfiguration(encryptionConfiguration *apiserverconfigv1.EncryptionConfiguration) ([]byte, error) {
	if encryptionConfiguration == nil {
		return nil, fmt.Errorf("EncryptionConfiguration object cannot be nil")
	}
	encoder := codecs.EncoderForVersion(jsonSerializer, apiserverconfigv1.SchemeGroupVersion)
	encryptionConfigurationData, err := runtime.Encode(encoder, encryptionConfiguration)
	if err != nil {
		return nil, fmt.Errorf("failed to encode EncryptionConfiguration: %w", err)
	}
	return encryptionConfigurationData, nil
}

// DecodeEncryptionConfiguration extracts an EncryptionConfiguration object from its serialized representation.
func DecodeEncryptionConfiguration(data []byte) (*apiserverconfigv1.EncryptionConfiguration, error) {
	encryptionConfiguration := &apiserverconfigv1.EncryptionConfiguration{}
	err := runtime.DecodeInto(codecs.UniversalDecoder(apiserverconfigv1.SchemeGroupVersion), data, encryptionConfiguration)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EncryptionConfiguration: %w", err)
	}
	return encryptionConfiguration, nil
}

// EncodeKMSConfiguration serializes a KMSConfiguration into an EncryptionConfiguration wrapper.
// We use an EncryptionConfiguration as an envelope type because KMSConfiguration is not a runtime.Object.
func EncodeKMSConfiguration(encryption *apiserverconfigv1.KMSConfiguration) ([]byte, error) {
	if encryption == nil {
		return nil, fmt.Errorf("KMSConfiguration object cannot be nil")
	}
	encryptionConfiguration := &apiserverconfigv1.EncryptionConfiguration{
		Resources: []apiserverconfigv1.ResourceConfiguration{
			{
				Providers: []apiserverconfigv1.ProviderConfiguration{
					{KMS: encryption},
				},
			},
		},
	}
	return EncodeEncryptionConfiguration(encryptionConfiguration)
}

// DecodeKMSConfiguration extracts a KMSConfiguration from its serialized EncryptionConfiguration wrapper.
// We use an EncryptionConfiguration as an envelope type because KMSConfiguration is not a runtime.Object.
func DecodeKMSConfiguration(data []byte) (*apiserverconfigv1.KMSConfiguration, error) {
	encryptionConfiguration, err := DecodeEncryptionConfiguration(data)
	if err != nil {
		return nil, err
	}
	// This should never happen, unless the object was not serialized with EncodeKMSConfiguration
	if len(encryptionConfiguration.Resources) != 1 || len(encryptionConfiguration.Resources[0].Providers) != 1 {
		return nil, fmt.Errorf("invalid KMS encryption config")
	}
	return encryptionConfiguration.Resources[0].Providers[0].KMS, nil
}

// EncodeInternalKMSPluginConfig serializes an InternalKMSPluginConfig into its
// internal envelope representation using Kubernetes codec infrastructure.
func EncodeInternalKMSPluginConfig(config state.InternalKMSPluginConfig) ([]byte, error) {
	envelope := &internalKMSPluginConfigEnvelope{
		Plugin:         config.Plugin,
		KMSPluginImage: config.KMSPluginImage,
	}
	encoder := codecs.EncoderForVersion(jsonSerializer, internalKMSPluginConfigGV)
	data, err := runtime.Encode(encoder, envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to encode internal KMS plugin config: %w", err)
	}
	return data, nil
}

// DecodeInternalKMSPluginConfig extracts an InternalKMSPluginConfig from its
// serialized envelope representation.
func DecodeInternalKMSPluginConfig(data []byte) (state.InternalKMSPluginConfig, error) {
	envelope := &internalKMSPluginConfigEnvelope{}
	err := runtime.DecodeInto(codecs.UniversalDecoder(internalKMSPluginConfigGV), data, envelope)
	if err != nil {
		return state.InternalKMSPluginConfig{}, fmt.Errorf("failed to decode internal KMS plugin config: %w", err)
	}
	return state.InternalKMSPluginConfig{
		Plugin:         envelope.Plugin,
		KMSPluginImage: envelope.KMSPluginImage,
	}, nil
}
