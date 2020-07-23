package secretspruner

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMinPodRevision(t *testing.T) {
	tests := []struct {
		name string
		pods []*corev1.Pod
		want int
	}{
		{"empty", nil, 0},
		{"one", []*corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"revision": "1"}}},
		}, 1},
		{"one without label", []*corev1.Pod{
			{},
		}, 0},
		{"many", []*corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"revision": "6"}}},
			{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"revision": "3"}}},
			{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"revision": "8"}}},
			{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"revision": "8"}}},
			{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"revision": "3"}}},
			{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"revision": "4"}}},
		}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := minPodRevision(tt.pods); got != tt.want {
				t.Errorf("minPodRevision() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSecretsToBePruned(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name           string
		minRevision    int
		secretPrefixes []string
		secrets        []*corev1.Secret
		want           []*corev1.Secret
	}{
		{"empty", 11, []string{"foo-"}, nil, nil},
		{"five", 11, []string{"foo-"}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-3"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-4"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-5"}},
		}, []*corev1.Secret{}},
		{"five old and some new", 11, []string{"foo-"}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-3"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-4"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-5"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-11"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-12"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-13"}},
		}, []*corev1.Secret{}},
		{"six", 11, []string{"foo-"}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-3"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-4"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-5"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-6"}},
		}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
		}},
		{"six foo and some unknown", 11, []string{"foo-"}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-3"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-4"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-5"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-6"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "unknown-7"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "unknown-8"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "unknown-9"}},
		}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
		}},
		{"five foo and bar", 11, []string{"foo-"}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-3"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-4"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-5"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-3"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-4"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-5"}},
		}, []*corev1.Secret{}},
		{"ten foo and bar", 11, []string{"foo-", "bar-"}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-3"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-4"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-5"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-6"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-7"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-8"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-9"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-10"}},
		}, []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-3"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bar-4"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "foo-5"}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secretsToBePruned(tt.minRevision, tt.secretPrefixes, tt.secrets)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("secretsToBePruned() got = %v, want %v", got, tt.want)
			}
		})
	}
}
