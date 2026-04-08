package apiservice

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"

	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	"github.com/openshift/library-go/pkg/operator/bootstrap"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/endpointcheck"
)

func preconditionsForEnabledAPIServices(endpointsListerForTargetNs corev1listers.EndpointsLister, configmapListerForKubeSystemNs corev1listers.ConfigMapLister) func(apiServices []*apiregistrationv1.APIService) (bool, error) {
	return func(apiServices []*apiregistrationv1.APIService) (bool, error) {
		areEndpointsPresent, err := checkEndpointsPresence(endpointsListerForTargetNs, apiServices)
		if !areEndpointsPresent || err != nil {
			return false, err
		}
		return bootstrap.IsBootstrapComplete(configmapListerForKubeSystemNs)
	}
}

func checkEndpointsPresence(endpointsLister corev1listers.EndpointsLister, apiServices []*apiregistrationv1.APIService) (bool, error) {
	type coordinate struct {
		namespace string
		name      string
	}

	coordinates := []coordinate{}
	for _, apiService := range apiServices {
		curr := coordinate{namespace: apiService.Spec.Service.Namespace, name: apiService.Spec.Service.Name}
		exists := false
		for _, j := range coordinates {
			if j == curr {
				exists = true
				break
			}
		}
		if !exists {
			coordinates = append(coordinates, curr)
		}
	}

	for _, curr := range coordinates {
		endpoints, err := endpointsLister.Endpoints(curr.namespace).Get(curr.name)
		if err != nil {
			return false, err
		}
		if len(endpoints.Subsets) == 0 {
			return false, nil
		}

		exists := false
		for _, subset := range endpoints.Subsets {
			if len(subset.Addresses) > 0 {
				exists = true
				break
			}
		}
		if !exists {
			return false, nil
		}
	}

	return true, nil
}

// checkDiscoveryForByAPIServices checks the given API services one by one,
// returning a list of relevant error messages.
//
// This function implements a retry mechanism to make the checks more robust
// to account for requests routed to obsolete pods, which is a known upstream issue:
//
//	https://github.com/kubernetes/kubernetes/issues/116965
//
// Regarding downstream, this affects e.g. OCPBUGS-23746 and surfaces as APIServices_Error status condition.
//
// TODO: Remove retries once the upstream issue is resolved.
func checkDiscoveryForByAPIServices(ctx context.Context, recorder events.Recorder, restclient rest.Interface, apiServices []*apiregistrationv1.APIService) []string {
	return checkDiscoveryForByAPIServicesWithCheckFn(ctx, recorder, restclient, apiServices, checkDiscoveryForAPIService)
}

// apiServiceCheckFunc checks a single API service and returns an error if it is not available.
type apiServiceCheckFunc func(ctx context.Context, restclient rest.Interface, apiService *apiregistrationv1.APIService, requestTimeout time.Duration) error

func checkDiscoveryForByAPIServicesWithCheckFn(ctx context.Context, recorder events.Recorder, restclient rest.Interface, apiServices []*apiregistrationv1.APIService, checkFn apiServiceCheckFunc) []string {
	missingMessages := []string{}
	attemptCount := uint64(3)
	for _, apiService := range apiServices {
		// Do the check attemptCount times. Each request uses a 10-second timeout and there is
		// a 5-second backoff between attempts, but shortened if the check failed with a timeout
		// (since the request already consumed wall-clock time).
		err := endpointcheck.Check(ctx, 10*time.Second, backoff.NewConstantBackOff(5*time.Second), attemptCount, func(ctx context.Context, requestTimeout time.Duration) error {
			return checkFn(ctx, restclient, apiService, requestTimeout)
		})
		if err != nil {
			groupVersionString := fmt.Sprintf("%s.%s", apiService.Spec.Group, apiService.Spec.Version)
			recorder.Warningf("OpenShiftAPICheckFailed", fmt.Sprintf("%q failed with %v", groupVersionString, err))
			missingMessages = append(missingMessages, fmt.Sprintf("%q is not ready: %v", groupVersionString, err))
			if ctx.Err() != nil {
				break
			}
			// Disable retries when a check fails. The subsequent ones will possibly fail for the same reason.
			attemptCount = 1
		}
	}

	return missingMessages
}

func checkDiscoveryForAPIService(ctx context.Context, restclient rest.Interface, apiService *apiregistrationv1.APIService, requestTimeout time.Duration) error {
	type statusErrTuple struct {
		status int
		err    error
	}

	var attempts = 5
	var resultsCh = make(chan statusErrTuple, attempts)

	var wg sync.WaitGroup
	wg.Add(attempts)

	for i := 0; i < attempts; i++ {
		go func() {
			var discoveryCtx context.Context
			var ctxCancelFn context.CancelFunc
			var statusCode int
			defer wg.Done()
			defer utilruntime.HandleCrash()

			discoveryCtx, ctxCancelFn = context.WithTimeout(ctx, requestTimeout)
			defer ctxCancelFn()

			result := restclient.Get().AbsPath("/apis/" + apiService.Spec.Group + "/" + apiService.Spec.Version).Do(discoveryCtx).StatusCode(&statusCode)
			resultsCh <- statusErrTuple{status: statusCode, err: result.Error()}
		}()
	}

	wg.Wait()
	close(resultsCh)

	var successfulRequests int
	var errs = []error{}
	for resTuple := range resultsCh {
		if resTuple.status != http.StatusOK {
			errs = append(errs, fmt.Errorf("an attempt failed with statusCode = %v: %w", resTuple.status, resTuple.err))
			continue
		}
		successfulRequests++
	}

	// we don't aim for a total availability
	// since the API servers got better and terminate requests gracefully
	// and since we fire 5 requests in parallel we expect at least 40% success rate
	if successfulRequests < 2 {
		return kerrors.NewAggregate(errs)
	}
	return nil
}
