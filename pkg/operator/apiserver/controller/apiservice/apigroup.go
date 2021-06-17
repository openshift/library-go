package apiservice

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	kerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	"github.com/openshift/library-go/pkg/operator/events"
)

func newEndpointPrecondition(kubeInformers kubeinformers.SharedInformerFactory) func(apiServices []*apiregistrationv1.APIService) (bool, error) {
	// this is outside the func so it always registers before the informers start
	endpointsLister := kubeInformers.Core().V1().Endpoints().Lister()

	type coordinate struct {
		namespace string
		name      string
	}

	return func(apiServices []*apiregistrationv1.APIService) (bool, error) {

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
}

func checkDiscoveryForByAPIServices(recorder events.Recorder, restclient rest.Interface, apiServices []*apiregistrationv1.APIService) []string {
	missingMessages := []string{}
	for _, apiService := range apiServices {
		err := checkDiscoveryForAPIService(restclient, apiService)
		if err != nil {
			groupVersionString := fmt.Sprintf("%s.%s", apiService.Spec.Group, apiService.Spec.Version)
			recorder.Warningf("OpenShiftAPICheckFailed", fmt.Sprintf("%q failed with %v", groupVersionString, err))
			missingMessages = append(missingMessages, fmt.Sprintf("%q is not ready: %v", groupVersionString, err))
		}
	}

	return missingMessages
}

func checkDiscoveryForAPIService(restclient rest.Interface, apiService *apiregistrationv1.APIService) error {
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
			var ctx context.Context
			var ctxCancelFn context.CancelFunc
			var statusCode int
			defer wg.Done()
			defer utilruntime.HandleCrash()

			ctx, ctxCancelFn = context.WithTimeout(context.TODO(), 25*time.Second)
			defer ctxCancelFn()

			result := restclient.Get().AbsPath("/apis/" + apiService.Spec.Group + "/" + apiService.Spec.Version).Do(ctx).StatusCode(&statusCode)
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
