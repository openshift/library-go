package manifestclient

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	serializerjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	clientscheme "k8s.io/client-go/kubernetes/scheme"
)

var k8sCoreScheme = clientscheme.Scheme
var k8sProtobufSerializer = protobuf.NewSerializer(k8sCoreScheme, k8sCoreScheme)

func init() {
	apiextensionsv1.AddToScheme(k8sCoreScheme)
}

func individualFromList(objList *unstructured.UnstructuredList, name string) (*unstructured.Unstructured, error) {
	individualKind := strings.TrimSuffix(objList.GetKind(), "List")

	for _, obj := range objList.Items {
		if obj.GetName() != name {
			continue
		}

		ret := obj.DeepCopy()
		ret.SetKind(individualKind)
		return ret, nil
	}

	return nil, fmt.Errorf("not found in this list")
}

func readListFile(sourceFS fs.FS, path string) (*unstructured.UnstructuredList, error) {
	content, err := fs.ReadFile(sourceFS, path)
	if err != nil {
		return nil, fmt.Errorf("unable to read %q: %w", path, err)
	}

	return decodeListObj(content)
}

func readIndividualFile(sourceFS fs.FS, path string) (*unstructured.Unstructured, error) {
	content, err := fs.ReadFile(sourceFS, path)
	if err != nil {
		return nil, fmt.Errorf("unable to read %q: %w", path, err)
	}

	return decodeIndividualObj(content)
}

var localScheme = runtime.NewScheme()
var codecs = serializer.NewCodecFactory(localScheme)

func decodeIndividualObj(content []byte) (*unstructured.Unstructured, error) {
	obj, _, err := codecs.UniversalDecoder().Decode(content, nil, &unstructured.Unstructured{})
	if err != nil {
		return nil, fmt.Errorf("unable to decode: %w", err)
	}
	return obj.(*unstructured.Unstructured), nil
}

func decodeListObj(content []byte) (*unstructured.UnstructuredList, error) {
	obj, _, err := codecs.UniversalDecoder().Decode(content, nil, &unstructured.UnstructuredList{})
	if err != nil {
		return nil, fmt.Errorf("unable to decode: %w", err)
	}
	return obj.(*unstructured.UnstructuredList), nil
}

func serializeIndividualObjToJSON(obj *unstructured.Unstructured) (string, error) {
	ret, err := json.MarshalIndent(obj.Object, "", "    ")
	if err != nil {
		return "", err
	}
	return string(ret) + "\n", nil
}

func serializeListObjToJSON(obj *unstructured.UnstructuredList) (string, error) {
	ret, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return "", err
	}
	return string(ret) + "\n", nil
}

func serializeAPIResourceListToJSON(obj *metav1.APIResourceList) (string, error) {
	ret, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return "", err
	}
	return string(ret) + "\n", nil
}

func convertRuntimeObjectToUnstructured(obj runtime.Object) (*unstructured.Unstructured, error) {
	serializer := serializerjson.NewSerializerWithOptions(serializerjson.DefaultMetaFactory, k8sCoreScheme, k8sCoreScheme, serializerjson.SerializerOptions{})
	buf, err := runtime.Encode(serializer, obj)
	if err != nil {
		return nil, err
	}
	unstructuredObj := &unstructured.Unstructured{}
	err = json.Unmarshal(buf, &unstructuredObj.Object)
	if err != nil {
		return nil, err
	}
	return unstructuredObj, nil
}

func decodeRequestBody(isProtobufEncoded bool, bodyContent []byte, kindInput schema.GroupVersionKind) (*unstructured.Unstructured, error) {
	codec := unstructured.UnstructuredJSONScheme
	var bodyObj runtime.Object
	var unstructuredObj *unstructured.Unstructured
	switch {
	case isProtobufEncoded:
		if strings.Contains(string(bodyContent), "DeleteOptions") {
			kindInput = schema.GroupVersionKind{
				Version: "v1",
				Kind:    "DeleteOptions",
			}
		}
		bodyObj, err := k8sCoreScheme.New(kindInput)
		if err != nil {
			return nil, fmt.Errorf("unable to create scheme: %w", err)
		}
		codecFactory := serializer.NewCodecFactory(k8sCoreScheme)
		codec := codecFactory.CodecForVersions(k8sProtobufSerializer, k8sProtobufSerializer, nil, kindInput.GroupVersion())
		bodyObj, _, err = codec.Decode(bodyContent, nil, bodyObj)
		if err != nil {
			return nil, fmt.Errorf("unable to decode body: %w", err)
		}

		unstructuredObj, err = convertRuntimeObjectToUnstructured(bodyObj)
		if err != nil {
			return nil, fmt.Errorf("unable to decode body: %w", err)
		}
	default:
		bodyObj, _, err := codec.Decode(bodyContent, nil, bodyObj)
		if err != nil {
			return nil, fmt.Errorf("unable to decode body: %w", err)
		}
		unstructuredObj = bodyObj.(*unstructured.Unstructured)
	}
	return unstructuredObj, nil
}
