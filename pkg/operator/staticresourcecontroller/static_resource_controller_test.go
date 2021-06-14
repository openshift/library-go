package staticresourcecontroller

import (
	"context"
	"github.com/davecgh/go-spew/spew"
	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/client/openshiftrestmapper"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/stretchr/testify/assert"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakecore "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/restmapper"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/diff"
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

func makePDBManifest() []byte {
	return []byte(`
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: foo
  namespace: abc
`)
}

func makeDeploymentManifest() []byte {
	return []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: etcd-quorum-guard
  namespace: openshift-etcd
spec:
  replicas: 3
  selector:
    matchLabels:
      k8s-app: etcd-quorum-guard
  strategy:
    rollingUpdate:
      maxSurge: 0
      maxUnavailable: 1
    type: RollingUpdate
  template:
    metadata:
      labels:
        name: etcd-quorum-guard
        k8s-app: etcd-quorum-guard
    spec:
      hostNetwork: true
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: k8s-app
                    operator: In
                    values:
                      - "etcd-quorum-guard"
              topologyKey: kubernetes.io/hostname
      nodeSelector:
        node-role.kubernetes.io/master: ""
      priorityClassName: "system-cluster-critical"
      terminationGracePeriodSeconds: 3
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
          operator: Exists
        - key: node.kubernetes.io/not-ready
          effect: NoExecute
          operator: Exists
        - key: node.kubernetes.io/unreachable
          effect: NoExecute
          operator: Exists
        - key: node-role.kubernetes.io/etcd
          operator: Exists
          effect: NoSchedule
      containers:
        - name: guard
          image: quay.io/openshift/origin-cli:latest
          imagePullPolicy: IfNotPresent
          terminationMessagePolicy: FallbackToLogsOnError
          volumeMounts:
            - mountPath: /var/run/secrets/etcd-client
              name: etcd-client
            - mountPath: /var/run/configmaps/etcd-ca
              name: etcd-ca
          command:
            - /bin/bash
          args:
            - -c
            - |
              # properly handle TERM and exit as soon as it is signaled
              set -euo pipefail
              trap 'jobs -p | xargs -r kill; exit 0' TERM
              sleep infinity & wait
          readinessProbe:
            exec:
              command:
                - /bin/sh
                - -c
                - |
                  declare -r health_endpoint="https://localhost:2379/health"
                  declare -r cert="/var/run/secrets/etcd-client/tls.crt"
                  declare -r key="/var/run/secrets/etcd-client/tls.key"
                  declare -r cacert="/var/run/configmaps/etcd-ca/ca-bundle.crt"
                  export NSS_SDB_USE_CACHE=no
                  [[ -z $cert || -z $key ]] && exit 1
                  curl --max-time 2 --silent --cert "${cert//:/\:}" --key "$key" --cacert "$cacert" "$health_endpoint" |grep '{ *"health" *: *"true" *}'
            initialDelaySeconds: 5
            periodSeconds: 5
            failureThreshold: 3
            timeoutSeconds: 3
          resources:
            requests:
              cpu: 10m
              memory: 5Mi
          securityContext:
            privileged: true
      volumes:
        - name: etcd-client
          secret:
            secretName: etcd-client
        - name: etcd-ca
          configMap:
            name: etcd-ca-bundle
		`)
}

// fakeOperatorInstance is a fake Operator instance that  fullfils the OperatorClient interface.
type fakeOperatorInstance struct {
	metav1.ObjectMeta
	Spec   opv1.OperatorSpec
	Status opv1.OperatorStatus
}

func makeFakeOperatorInstance() *fakeOperatorInstance {
	instance := &fakeOperatorInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cluster",
			Generation: 0,
		},
		Spec: opv1.OperatorSpec{
			ManagementState: opv1.Managed,
		},
		Status: opv1.OperatorStatus{},
	}
	return instance
}

//func makeResourceConditionalMap() []resourceapply.ResourceConditionalMap {
//
//}
//
//func CreatePDBConditional() resourceapply.ConditionalFunction {
//	return func() bool {return true}
//}

func TestStaticResourceController_Sync(t *testing.T) {
	testCases := []struct {
		name                   string
		resourceConditionalMap []resourceapply.ResourceConditionalMap
		existing               []runtime.Object
		verifyActions          func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name: "static resource with no conditionals, create resource normally",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: nil,
					CreateConditionalFunc: nil,
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
				expected := &policyv1.PodDisruptionBudget{
					TypeMeta: metav1.TypeMeta{
						Kind:       "PodDisruptionBudget",
						APIVersion: "policy/v1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "abc"},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*policyv1.PodDisruptionBudget)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(diff.ObjectDiff(expected, actual))
				}
			},
		},
		{
			name: "static resource with delete conditional and no create conditional, delete will be honored",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: func() bool { return true },
					CreateConditionalFunc: nil,
				},
			},
			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "abc",
					},
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with delete conditional and create conditional, delete will be honored",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: func() bool { return true },
					CreateConditionalFunc: func() bool { return true },
				},
			},
			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "abc",
					},
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with no delete conditional and create conditional, creation happens",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: nil,
					CreateConditionalFunc: func() bool { return true },
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with no delete conditional and false create conditional, no creation",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: nil,
					CreateConditionalFunc: func() bool { return false },
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with false delete conditional and false create conditional, no creation",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: func() bool { return false },
					CreateConditionalFunc: func() bool { return false },
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with false delete conditional and false create conditional, existing resource, leave it as is",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: func() bool { return false },
					CreateConditionalFunc: func() bool { return false },
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with true delete conditional and false create conditional, no resource existing, " +
				"deletion is honored, no resource created",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: func() bool { return true },
					CreateConditionalFunc: func() bool { return false },
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with true delete conditional and false create conditional, resource existing, " +
				"deletion is honored",
			resourceConditionalMap: []resourceapply.ResourceConditionalMap{
				{
					File:                  "pdb.yaml",
					DeleteConditionalFunc: func() bool { return true },
					CreateConditionalFunc: func() bool { return false },
				},
			},
			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "abc",
					},
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("delete", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
	}
	for _, tc := range testCases {
		//recorder := events.NewInMemoryRecorder("test")
		t.Run(tc.name, func(t *testing.T) {
			coreClient := fakecore.NewSimpleClientset(tc.existing...)
			//coreInformerFactory := coreinformers.NewSharedInformerFactory(coreClient, 0 )
			opInstance := makeFakeOperatorInstance()
			fakeOperatorClient := v1helpers.NewFakeOperatorClient(&opInstance.Spec, &opInstance.Status, nil)
			c := &StaticResourceController{
				name:                    "static-resource-controller",
				manifests:               func(name string) ([]byte, error) { return makePDBManifest(), nil },
				resourceConditionalMaps: tc.resourceConditionalMap,
				ignoreNotFoundOnCreate:  false,
				operatorClient:          fakeOperatorClient,
				clients:                 (&resourceapply.ClientHolder{}).WithKubernetes(coreClient),
				eventRecorder:           events.NewInMemoryRecorder("test"),
				factory:                 nil,
				categoryExpander:        nil,
			}
			err := c.Sync(context.TODO(), factory.NewSyncContext("static-resource-controller",
				events.NewInMemoryRecorder("test")))
			if err != nil {
				t.Errorf("failed sync, %v for %v", err, tc.name)
			}
			tc.verifyActions(coreClient.Actions(), t)
		})
	}
}
