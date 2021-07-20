package customroute

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"reflect"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"

	"github.com/openshift/library-go/pkg/route/routeapihelpers"
	"github.com/openshift/library-go/pkg/route/routecomponenthelpers"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

func ensureDefaultConditions(conditions []metav1.Condition) []metav1.Condition {
	for _, conditionType := range []string{"Progressing", "Degraded"} {
		condition := findCondition(conditions, conditionType)
		if condition == nil {
			conditions = append(conditions, metav1.Condition{
				LastTransitionTime: metav1.Now(),
				Type:               conditionType,
				Status:             metav1.ConditionFalse,
				Reason:             "AsExpected",
				Message:            "All is well",
			})
		}
	}
	return conditions
}

func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func checkErrorsConfiguringCustomRoute(errors []error) []metav1.Condition {
	if len(errors) != 0 {
		now := metav1.Now()
		return []metav1.Condition{
			{
				LastTransitionTime: now,
				Type:               "Degraded",
				Status:             metav1.ConditionTrue,
				Reason:             "CustomRouteError",
				Message:            fmt.Sprintf("Error Configuring custom route: %v", errors),
			},
			{
				LastTransitionTime: now,
				Type:               "Progressing",
				Status:             metav1.ConditionFalse,
				Reason:             "CustomRouteError",
				Message:            fmt.Sprintf("Error Configuring custom route: %v", errors),
			},
		}
	}
	return nil
}

func checkIngressURI(ingressConfig *configv1.Ingress, route *routev1.Route) []metav1.Condition {
	if _, _, err := routeapihelpers.IngressURI(route, route.Spec.Host); err != nil {
		condition := &metav1.Condition{
			LastTransitionTime: metav1.Now(),
			Type:               "Progressing",
			Status:             "True",
			Reason:             "RouteNotAdmitted",
			Message:            fmt.Sprintf("Route not admitted: %v", err),
		}
		componentRoute := routecomponenthelpers.GetComponentRouteStatus(ingressConfig, "openshift-authentication", "oauth-openshift")
		if componentRoute != nil {
			degradeIfTimeElapsed(componentRoute.Conditions, condition, time.Minute*5)
		}
		return []metav1.Condition{*condition}
	}
	return nil
}

// degradeIfTimeElapsed checks if the condition matching this error (same type, reason and message)
// was found in the set of conditions and its `lastTransitionTime` appeared longer than
// `maxAge` ago, if so the condition's type is set to "Degraded"
func degradeIfTimeElapsed(conditions []metav1.Condition, condition *metav1.Condition, maxAge time.Duration) {
	for i := range conditions {
		if conditions[i].Reason == condition.Reason &&
			conditions[i].Message == condition.Message &&
			conditions[i].Type == condition.Type &&
			!condition.LastTransitionTime.IsZero() &&
			condition.LastTransitionTime.Add(maxAge).Before(condition.LastTransitionTime.Time) {
			condition.Type = "Degraded"
		}
	}
}

func checkRouteAvailablity(secretLister corev1listers.SecretLister, ingressConfig *configv1.Ingress, route *routev1.Route) []metav1.Condition {
	now := metav1.Now()
	if err := routeAvailablity(secretLister, route.Spec.Host, ingressConfig); err != nil {
		condition := &metav1.Condition{
			LastTransitionTime: now,
			Type:               "Progressing",
			Status:             "True",
			Reason:             "ErrorReachingOutToService",
			Message:            fmt.Sprintf("unexpected error at %s: %v", route.Spec.Host, err),
		}
		componentRoute := routecomponenthelpers.GetComponentRouteStatus(ingressConfig, "openshift-authentication", "oauth-openshift")
		if componentRoute != nil {
			degradeIfTimeElapsed(componentRoute.Conditions, condition, time.Minute*5)
		}
		return []metav1.Condition{*condition}

	}
	return nil
}

func routeAvailablity(secretLister corev1listers.SecretLister, host string, ingress *configv1.Ingress) error {
	url := "https://" + host + "/healthz"

	reqCtx, cancel := context.WithTimeout(context.TODO(), 10*time.Second) // avoid waiting forever
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	certBytes, _, _, err := routecomponenthelpers.GetActiveRouterCertKeyBytes(secretLister, ingress, "openshift-authentication", "v4-0-config-system-router-certs", "v4-0-config-system-custom-router-certs")
	if err != nil {
		return err
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM([]byte(certBytes)); !ok {
		return err
	}

	httpClient := http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		},
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("request against %s returned %d instead of 200", url, resp.StatusCode)
	}

	if resp.TLS == nil {
		return fmt.Errorf("unable to retrieve TLS information from %s", url)
	}

	// Compare the certificates served against those defined in the secret
	certs, err := parseCertificates(certBytes)
	if err != nil {
		return err
	}

	for _, expectedCert := range resp.TLS.PeerCertificates {
		found := false
		for _, cert := range certs {
			if reflect.DeepEqual(expectedCert, cert) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected cert not found")
		}
	}

	return nil
}

func parseCertificates(keyData []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	for block, keyData := pem.Decode(keyData); block != nil; block, keyData = pem.Decode(keyData) {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("data does not contain any valid certificates")
	}
	return certs, nil
}
