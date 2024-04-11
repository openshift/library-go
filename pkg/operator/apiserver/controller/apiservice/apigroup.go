package apiservice

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	"github.com/openshift/library-go/pkg/operator/bootstrap"
	"github.com/openshift/library-go/pkg/operator/events"
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

func checkDiscoveryForByAPIServices(ctx context.Context, recorder events.Recorder, restclient rest.Interface, apiServices []*apiregistrationv1.APIService) []string {
	missingMessages := []string{}
	for _, apiService := range apiServices {
		err := checkDiscoveryForAPIService(ctx, restclient, apiService)
		if err != nil {
			groupVersionString := fmt.Sprintf("%s.%s", apiService.Spec.Group, apiService.Spec.Version)
			recorder.Warningf("OpenShiftAPICheckFailed", fmt.Sprintf("%q failed with %v", groupVersionString, err))
			missingMessages = append(missingMessages, fmt.Sprintf("%q is not ready: %v", groupVersionString, err))
		}
	}

	return missingMessages
}

func checkDiscoveryForAPIService(ctx context.Context, restclient rest.Interface, apiService *apiregistrationv1.APIService) error {
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

			discoveryCtx, ctxCancelFn = context.WithTimeout(ctx, 25*time.Second)
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
			errs = append(errs, fmt.Errorf("an attempt failed with statusCode = %v, err = %v", resTuple.status, resTuple.err))
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
