package resourceapply

import (
	"context"

	routev1 "github.com/openshift/api/route/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

// ApplyRoute applies the required Route to the cluster.
func ApplyRoute(ctx context.Context, client routeclient.RouteInterface, recorder events.Recorder, required *routev1.Route) (*routev1.Route, bool, error) {
	existing, err := client.Get(ctx, required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := client.Create(ctx, required, metav1.CreateOptions{})
		reportCreateEvent(recorder, required, err)
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()
	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)

	// this guarantees that route.Spec.Host is set to the current canonical host
	if *modified || !equality.Semantic.DeepEqual(existingCopy.Spec, required.Spec) {
		if klog.V(4).Enabled() {
			klog.Infof("Route %q changes: %s", existing.Name, JSONPatchRouteNoError(existing, existingCopy))
		}
		// be careful not to print route.spec as it many contain secrets
		existingCopy.Spec = required.Spec
		actual, err := client.Update(ctx, existingCopy, metav1.UpdateOptions{})
		reportUpdateEvent(recorder, required, err)
		return actual, true, err
	}

	return existing, false, nil
}
