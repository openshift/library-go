package staticresourcecontroller

import (
	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/client/openshiftrestmapper"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/restmapper"
	"testing"
)

func TestRelatedObjects(t *testing.T) {
	sa := `apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-ebs-csi-driver-operator
  namespace: openshift-cluster-csi-drivers
`

	secret := `apiVersion: v1
kind: Secret
metadata:
  name: aws-ebs-csi-driver-operator
  namespace: openshift-cluster-csi-drivers
`
	expected := []configv1.ObjectReference{
		{
			Group:     "",
			Resource:  "serviceaccounts",
			Namespace: "openshift-cluster-csi-drivers",
			Name:      "aws-ebs-csi-driver-operator",
		},
	}
	expander := restmapper.SimpleCategoryExpander{
		Expansions: map[string][]schema.GroupResource{
			"all": {
				{Group: "", Resource: "secrets"},
			},
		},
	}
	restMapper := openshiftrestmapper.NewOpenShiftHardcodedRESTMapper(nil)
	operatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{},
		&operatorv1.OperatorStatus{},
		nil,
	)
	assets := map[string]string{"secret": secret, "sa": sa}
	readBytesFromString := func(filename string) ([]byte, error) {
		return []byte(assets[filename]), nil
	}

	src := NewStaticResourceController("", readBytesFromString, []string{"secret", "sa"}, nil, operatorClient, events.NewInMemoryRecorder(""))
	src = src.AddRESTMapper(restMapper).AddCategoryExpander(expander)
	res, _ := src.RelatedObjects()
	assert.ElementsMatch(t, expected, res)
}
