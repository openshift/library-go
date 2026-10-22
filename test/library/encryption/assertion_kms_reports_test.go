package encryption

import (
	"context"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestAssertKMSHealthReportsWaitsForFreshReportsOnEveryNode(t *testing.T) {
	for _, namespace := range []string{"openshift-kube-apiserver-operator", "openshift-authentication-operator"} {
		t.Run(namespace, func(t *testing.T) {
			t.Parallel()
			operandNamespace := operandNamespaceForOperator(namespace)
			cr := operatorCRForNamespace(t, namespace)
			kube := kubefake.NewSimpleClientset(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "encryption-key-" + operandNamespace + "-4", Namespace: "openshift-config-managed",
					Labels: map[string]string{"encryption.apiserver.operator.openshift.io/component": operandNamespace},
				},
			})
			for _, node := range []string{"node-1", "node-2"} {
				_, err := kube.CoreV1().Pods(operandNamespace).Create(context.Background(), &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: node, Labels: map[string]string{"apiserver": "true"}},
					Spec:       corev1.PodSpec{NodeName: node},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				}, metav1.CreateOptions{})
				require.NoError(t, err)
			}
			client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			reads := 0
			client.PrependReactor("get", cr.gvr.Resource, func(clienttesting.Action) (bool, runtime.Object, error) {
				reads++
				reports := []operatorv1.KMSPluginHealthReport{
					{NodeName: "node-1", KeyID: "4", Status: operatorv1.KMSPluginHealthStatusHealthy, RemoteKeyID: "remote-key", LastCheckedTime: metav1.NewTime(time.Now().Add(time.Minute))},
					{NodeName: "node-2", KeyID: "4", Status: operatorv1.KMSPluginHealthStatusHealthy, RemoteKeyID: "remote-key", LastCheckedTime: metav1.NewTime(time.Now().Add(time.Minute))},
				}
				switch reads {
				case 1: // Healthy reports from the previous provider must not pass.
					reports[0].KeyID, reports[1].KeyID = "3", "3"
				case 2: // The current key must have been checked after the assertion starts.
					reports[0].LastCheckedTime = metav1.NewTime(time.Now().Add(-time.Minute))
				case 3: // A healthy report from only one node is insufficient.
					reports = reports[:1]
				case 4:
					reports[1].Status = operatorv1.KMSPluginHealthStatusUnhealthy
				case 5:
					reports[1].RemoteKeyID = ""
				}
				raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&operatorv1.KMSEncryptionStatus{HealthReports: reports})
				if err != nil {
					return true, nil, err
				}
				obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
				if err := unstructured.SetNestedMap(obj.Object, raw, cr.encryptionStatusPath...); err != nil {
					return true, nil, err
				}
				return true, obj, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			AssertKMSHealthReports(ctx, t, ClientSet{Kube: kube, DynamicClient: client}, namespace)
			require.Equal(t, 6, reads, "must wait for fresh healthy reports for the new key on both nodes")
		})
	}
}
