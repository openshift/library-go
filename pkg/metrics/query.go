package metrics

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	kapierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	policyclientv1beta1 "k8s.io/client-go/kubernetes/typed/policy/v1beta1"

	"github.com/prometheus/common/model"
)

func LocatePrometheus(client *kubernetes.Clientset) (url, bearerToken string, ok bool) {
	_, err := client.CoreV1().Services("openshift-monitoring").Get("prometheus-k8s", metav1.GetOptions{})
	if kapierrs.IsNotFound(err) {
		return "", "", false
	}

	for i := 0; i < 30; i++ {
		secrets, err := client.CoreV1().Secrets("openshift-monitoring").List(metav1.ListOptions{})
		if err != nil {
			return "", "", false
		}
		for _, secret := range secrets.Items {
			if secret.Type != corev1.SecretTypeServiceAccountToken {
				continue
			}
			if !strings.HasPrefix(secret.Name, "prometheus-") {
				continue
			}
			bearerToken = string(secret.Data[corev1.ServiceAccountTokenKey])
			break
		}
		if len(bearerToken) == 0 {
			time.Sleep(time.Second)
			continue
		}
	}
	if len(bearerToken) == 0 {
		return "", "", false
	}

	return "https://prometheus-k8s.openshift-monitoring.svc:9091", bearerToken, true
}

const waitForPrometheusStartSeconds = 240

type prometheusResponse struct {
	Status string                 `json:"status"`
	Data   prometheusResponseData `json:"data"`
}

type prometheusResponseData struct {
	ResultType string       `json:"resultType"`
	Result     model.Vector `json:"result"`
}

func getBearerTokenURLViaPod(kclient *kubernetes.Clientset, servingcertsecret, servingcertsecretns, ns, execPodName, url, bearer string) ([]byte, error) {
	//cmd := fmt.Sprintf("curl -s -k -H 'Authorization: Bearer %s' %q", bearer, url)
	// Retrieve the cert and key PEM of the current CA via kube-controller-manager-operator serving-cert secret
	secret, err := kclient.CoreV1().Secrets(servingcertsecretns).Get(servingcertsecret, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error retrieving signing key secret: %v", err)
	}
	cert := secret.Data[corev1.TLSCertKey]
	key := secret.Data[corev1.TLSPrivateKeyKey]

	cfg, err := tlsConfig(t, cert, key)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: cfg,
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", bearer)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("curl command failed: %v\n%v", err, resp)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	return body, nil
}

// RunPrometheusQuery is similar to runQueries that lives in origin/test/extended/prometheus
// example: query := `ALERTS{alertstate="pending",alertname="PodDisruptionBudgetAtLimit",severity="warning"} == 1`
// TODO: will want a struct for all these
func RunPrometheusQuery(kclient *kubernetes.Clientset, query, servingcertsecret, servingcertsecretns, ns, execPodName, baseURL, bearerToken string, expected bool) error {
	// expect all correct metrics within a reasonable time period
	var err error
	for i := 0; i < waitForPrometheusStartSeconds; i++ {
		//TODO when the http/query apis discussed at https://github.com/prometheus/client_golang#client-for-the-prometheus-http-api
		// and introduced at https://github.com/prometheus/client_golang/blob/master/api/prometheus/v1/api.go are vendored into
		// openshift/origin, look to replace this homegrown http request / query param with that API
		contents, err := getBearerTokenURLViaPod(t, kclient, servingcertsecret, servingcertsecretns, ns, execPodName, fmt.Sprintf("%s/api/v1/query?%s", baseURL, (url.Values{"query": []string{query}}).Encode()), bearerToken)
		if err != nil {
			return err
		}
		result := prometheusResponse{}
		json.Unmarshal(contents, &result)
		metrics := result.Data.Result

		if (len(metrics) > 0 && !expected) || (len(metrics) == 0 && expected) {
			err = fmt.Errorf("promQL query: %s had reported incorrect results: %v", query, metrics)
		}

		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	return err
}

func tlsConfig(cert, key []byte) (*tls.Config, error) {
	certFile, err := ioutil.TempFile(os.TempDir(), "testtlscert-")
	if err != nil {
		return nil, err
	}
	keyFile, err := ioutil.TempFile(os.TempDir(), "testtlskey-")
	if err != nil {
		return nil, err
	}
	if _, err = certFile.Write(cert); err != nil {
		return nil, err
	}

	if err := certFile.Close(); err != nil {
		return nil, err
	}
	if _, err = keyFile.Write(key); err != nil {
		return nil, err
	}

	if err := keyFile.Close(); err != nil {
		return nil, err
	}

	tlscert, err := tls.LoadX509KeyPair(certFile.Name(), keyFile.Name())
	if err != nil {
		return nil, fmt.Errorf("unable to use specified client cert (%s) & key (%s): %s", certFile.Name(), keyFile.Name(), err)
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	tlsConfig.Certificates = []tls.Certificate{tlscert}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}
