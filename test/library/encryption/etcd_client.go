package encryption

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/etcd/client/v3"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
)

type EtcdClient interface {
	Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error)
}

func NewEtcdClient(kubeClient kubernetes.Interface) EtcdClient {
	return &etcdWrapper{kubeClient: kubeClient}
}

type etcdWrapper struct {
	kubeClient kubernetes.Interface
}

func (e *etcdWrapper) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	// Port-forwarding and etcd requests go through the kube-apiserver, which can be
	// briefly unavailable during a revision rollout on SNO. Retry creating the
	// client and the etcd request to tolerate this transient disruption.
	var resp *clientv3.GetResponse
	// in theory the max time we tolerate disruption on an SNO cluster is 60 seconds
	// so we set the timeout to 5 min just in case
	err := onErrorWithTimeout(5*time.Minute, func(error) bool {
		return ctx.Err() == nil
	}, func() error {
		// we need to rebuild this port-forward based client every time so we can tolerate API server rollouts
		clientInternal, done, err := e.newEtcdClientInternal(ctx)
		if err != nil {
			return fmt.Errorf("failed to build port-forward based etcd client: %v", err)
		}
		defer done()
		resp, err = clientInternal.Get(ctx, key, opts...)
		return err
	})
	return resp, err
}

func (e *etcdWrapper) newEtcdClientInternal(ctx context.Context) (EtcdClient, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, "oc", "port-forward", "service/etcd", ":2379", "-n", "openshift-etcd")

	var etcdClient3 *clientv3.Client
	done := func() {
		if etcdClient3 != nil {
			// release the etcd client's gRPC connection and background goroutines
			_ = etcdClient3.Close()
		}
		cancel()
		_ = cmd.Wait() // wait to clean up resources but ignore returned error since cancel kills the process
	}

	var err error // so we can clean up on error
	defer func() {
		if err != nil {
			done()
		}
	}()

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	if err = cmd.Start(); err != nil {
		return nil, nil, err
	}

	scanner := bufio.NewScanner(stdOut)
	if !scanner.Scan() {
		return nil, nil, fmt.Errorf("failed to scan port forward std out")
	}
	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}
	output := scanner.Text()

	port := strings.TrimSuffix(strings.TrimPrefix(output, "Forwarding from 127.0.0.1:"), " -> 2379")
	_, err = strconv.Atoi(port)
	if err != nil {
		return nil, nil, fmt.Errorf("port forward output not in expected format: %s", output)
	}

	coreV1 := e.kubeClient.CoreV1()
	etcdConfigMap, err := coreV1.ConfigMaps("openshift-config").Get(ctx, "etcd-ca-bundle", metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	etcdSecret, err := coreV1.Secrets("openshift-config").Get(ctx, "etcd-client", metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	tlsConfig, err := restclient.TLSConfigFor(&restclient.Config{
		TLSClientConfig: restclient.TLSClientConfig{
			CertData: etcdSecret.Data[corev1.TLSCertKey],
			KeyData:  etcdSecret.Data[corev1.TLSPrivateKeyKey],
			CAData:   []byte(etcdConfigMap.Data["ca-bundle.crt"]),
		},
	})
	if err != nil {
		return nil, nil, err
	}

	etcdClient3, err = clientv3.New(clientv3.Config{
		Endpoints:   []string{"https://127.0.0.1:" + port},
		DialTimeout: 30 * time.Second,
		TLS:         tlsConfig,
	})
	if err != nil {
		return nil, nil, err
	}

	return etcdClient3.KV, done, nil
}
