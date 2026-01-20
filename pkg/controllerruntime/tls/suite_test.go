/*
Copyright 2026 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	configv1 "github.com/openshift/api/config/v1"
	// Import to ensure CRD manifests are vendored (Go prunes non-Go files otherwise)
	_ "github.com/openshift/api/config/v1/zz_generated.crd-manifests"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	cfg            *rest.Config
	k8sClient      client.Client
	testEnv        *envtest.Environment
	testScheme     *runtime.Scheme
	ctx            = context.Background()
	managerOptions ctrl.Options
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "..", "vendor", "github.com", "openshift", "api", "config", "v1", "zz_generated.crd-manifests"),
		},
		ErrorIfCRDPathMissing: true,

		// Automatically download envtest binaries (etcd, kube-apiserver) if not present.
		// Uses OpenShift's envtest releases which include OpenShift-specific patches.
		DownloadBinaryAssets:         true,
		BinaryAssetsDirectory:        filepath.Join(os.TempDir(), "kubebuilder-envtest"),
		DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/openshift/api/master/envtest-releases.yaml",
	}

	testScheme = scheme.Scheme
	Expect(configv1.Install(testScheme)).To(Succeed())

	managerOptions = ctrl.Options{
		Scheme: testScheme,
		Metrics: server.Options{
			BindAddress: "0",
		},
		Controller: config.Controller{
			SkipNameValidation: ptr.To(true),
		},
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: testScheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	komega.SetClient(k8sClient)
	komega.SetContext(ctx)
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
