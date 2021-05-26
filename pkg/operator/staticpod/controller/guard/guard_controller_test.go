package guard

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	fakecore "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/pointer"
)

func readBytesFromFile(t *testing.T, filename string) []byte {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestGuardController_ensureDeploymentGuard(t *testing.T) {
	clusterConfigFullHA := corev1.ConfigMap{TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterConfigName,
			Namespace: clusterConfigNamespace,
		}, Data: map[string]string{clusterConfigKey: `apiVersion: v1
controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: 3`}}
	var changedPDB *policyv1.PodDisruptionBudget
	pdb := resourceread.ReadPodDisruptionBudgetV1OrDie(readBytesFromFile(t, "./testdata/guard-pdb.yaml"))
	changedPDB = pdb.DeepCopy()
	changedPDB.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-changed": "etcd-quorum-guard"}}
	deployment := resourceread.ReadDeploymentV1OrDie(readBytesFromFile(t, "./testdata/guard-deployment.yaml"))
	deployment.ObjectMeta.Annotations = map[string]string{"operator.openshift.io/spec-hash": "c0fd9250c0d0695111ff9beae1d223c3e1ea50131533b564fc92a5f009e9b552",
		"operator.openshift.io/pull-spec": "quay.io/openshift/origin-cli:latest"}
	deployment.ObjectMeta.Labels = map[string]string{}
	changedDeployment := deployment.DeepCopy()
	changedDeployment.Spec.Replicas = pointer.Int32Ptr(1)

	fakeInfraIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	haInfra := &configv1.Infrastructure{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: infrastructureClusterName,
		},
		Status: configv1.InfrastructureStatus{
			ControlPlaneTopology: configv1.HighlyAvailableTopologyMode},
	}
	operatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{
			ManagementState: operatorv1.Managed,
		},
		&operatorv1.OperatorStatus{},
		nil)

	type fields struct {
		client         kubernetes.Interface
		infraObj       *configv1.Infrastructure
		operatorClient v1helpers.OperatorClient
	}
	tests := []struct {
		name                 string
		fields               fields
		wantErr              bool
		expectedHATopology   configv1.TopologyMode
		expectedEvents       int
		expectedReplicaCount int
	}{
		{
			name: "test ensureEtcdGuard - deployment not exists but pdb exists",
			fields: fields{
				client:   fakecore.NewSimpleClientset(&clusterConfigFullHA, pdb),
				infraObj: haInfra, operatorClient: operatorClient,
			},
			expectedHATopology: configv1.HighlyAvailableTopologyMode, expectedEvents: 1, wantErr: false, expectedReplicaCount: 3,
		},
		{
			name: "test ensureEtcdGuard - deployment was changed and pdb exists",
			fields: fields{
				client:   fakecore.NewSimpleClientset(changedDeployment, pdb, &clusterConfigFullHA),
				infraObj: haInfra, operatorClient: operatorClient,
			},
			expectedHATopology: configv1.HighlyAvailableTopologyMode, expectedEvents: 1, wantErr: false, expectedReplicaCount: 3,
		},
		{
			name: "test ensureEtcdGuard - deployment and pdb were changed",
			fields: fields{
				client:   fakecore.NewSimpleClientset(changedDeployment, changedPDB, &clusterConfigFullHA),
				infraObj: haInfra, operatorClient: operatorClient,
			},
			expectedHATopology: configv1.HighlyAvailableTopologyMode, expectedEvents: 2, wantErr: false, expectedReplicaCount: 3,
		},
		{
			name: "test ensureEtcdGuard - nonHAmod",
			fields: fields{
				client: fakecore.NewSimpleClientset(),
				infraObj: &configv1.Infrastructure{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: infrastructureClusterName,
					},
					Status: configv1.InfrastructureStatus{
						ControlPlaneTopology: configv1.SingleReplicaTopologyMode},
				},
				operatorClient: operatorClient,
			},
			expectedHATopology: configv1.SingleReplicaTopologyMode, expectedEvents: 0, wantErr: false, expectedReplicaCount: 0,
		},
		{
			name: "test ensureEtcdGuard - ha mod not set, nothing exists",
			fields: fields{
				client: fakecore.NewSimpleClientset(&clusterConfigFullHA),
				infraObj: &configv1.Infrastructure{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: infrastructureClusterName,
					},
					Status: configv1.InfrastructureStatus{}},
				operatorClient: operatorClient,
			},
			expectedHATopology: "", expectedEvents: 0, wantErr: true, expectedReplicaCount: 0,
		},
		{
			name: "test ensureEtcdGuard - 5 replicas and nothing exists",
			fields: fields{
				client: fakecore.NewSimpleClientset(&corev1.ConfigMap{TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:      clusterConfigName,
						Namespace: clusterConfigNamespace,
					}, Data: map[string]string{clusterConfigKey: `apiVersion: v1
controlPlane:
 hyperthreading: Enabled
 name: master
 replicas: 5`}}),
				infraObj: haInfra, operatorClient: operatorClient,
			},
			expectedHATopology: configv1.HighlyAvailableTopologyMode, expectedEvents: 2, wantErr: false, expectedReplicaCount: 5,
		},
		{
			name: "test ensureEtcdGuard - get clusterConfig not exists",
			fields: fields{
				client:   fakecore.NewSimpleClientset(),
				infraObj: haInfra, operatorClient: operatorClient,
			},
			expectedHATopology: configv1.HighlyAvailableTopologyMode, expectedEvents: 0, wantErr: true,
		},
		{
			name: "test ensureEtcdGuard - get replicas count key not found",
			fields: fields{
				client: fakecore.NewSimpleClientset(&corev1.ConfigMap{TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:      clusterConfigName,
						Namespace: clusterConfigNamespace,
					}, Data: map[string]string{clusterConfigKey: `apiVersion: v1
controlPlane:
 hyperthreading: Enabled
 name: master`}}),
				infraObj: haInfra, operatorClient: operatorClient,
			},
			expectedHATopology: configv1.HighlyAvailableTopologyMode, expectedEvents: 0, wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := events.NewInMemoryRecorder("test")

			if err := fakeInfraIndexer.Add(tt.fields.infraObj); err != nil {
				t.Fatal(err)
			}

			c := &GuardController{
				kubeClient:           tt.fields.client,
				operatorClient:       tt.fields.operatorClient,
				infrastructureLister: configv1listers.NewInfrastructureLister(fakeInfraIndexer),
				deploymentManifest:   readBytesFromFile(t, "./testdata/guard-deployment.yaml"),
				pdbManifest:          readBytesFromFile(t, "./testdata/guard-pdb.yaml"),
			}
			err := c.Sync(context.TODO(), factory.NewSyncContext("test", recorder))
			if (err != nil) != tt.wantErr {
				t.Errorf("ensureEtcdGuard() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(recorder.Events()) != tt.expectedEvents {
				t.Errorf("number of events %d and expected %d, events %v", len(recorder.Events()), tt.expectedEvents, recorder.Events())
				return
			}

			if c.clusterTopology != tt.expectedHATopology {
				t.Errorf("cluster HA topology is %q and expected %q", c.clusterTopology, tt.expectedHATopology)
				return
			}

			if c.replicaCount != tt.expectedReplicaCount {
				t.Errorf("replicaCount is %d and expected is %d", c.replicaCount, tt.expectedReplicaCount)
				return
			}
		})
	}
}
