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
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	configv1 "github.com/openshift/api/config/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var _ = Describe("TLSSecurityProfileWatcher controller", func() {
	var (
		mgrCancel    context.CancelFunc
		mgrDone      chan struct{}
		mgr          manager.Manager
		apiServer    *configv1.APIServer
		shutdownOnce sync.Once
		shutdownCnt  atomic.Int32
	)

	BeforeEach(func() {
		var err error

		// Create the APIServer object.
		apiServer = &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{
				Name: APIServerName,
			},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileIntermediateType,
				},
			},
		}
		Expect(k8sClient.Create(ctx, apiServer)).To(Succeed())

		// Create a new manager for each test.
		mgr, err = ctrl.NewManager(cfg, managerOptions)
		Expect(err).NotTo(HaveOccurred())

		// Reset shutdown tracking.
		shutdownOnce = sync.Once{}
		shutdownCnt.Store(0)
	})

	AfterEach(func() {
		// Stop the manager if it's running.
		if mgrCancel != nil {
			mgrCancel()
			<-mgrDone
		}

		// Clean up the APIServer object.
		Expect(k8sClient.Delete(ctx, apiServer)).To(Succeed())
	})

	startManager := func(initialProfile configv1.TLSProfileSpec) {
		var mgrCtx context.Context
		mgrCtx, mgrCancel = context.WithCancel(ctx)
		mgrDone = make(chan struct{})

		// Set up the TLS security profile watcher controller.
		watcher := &TLSSecurityProfileWatcher{
			Client:                mgr.GetClient(),
			InitialTLSProfileSpec: initialProfile,
			Shutdown: func() {
				// Use sync.Once to ensure we only count the first call,
				// similar to how context.CancelFunc is idempotent.
				shutdownOnce.Do(func() {
					shutdownCnt.Add(1)
				})
				// Always cancel the context (this is idempotent).
				mgrCancel()
			},
		}
		Expect(watcher.SetupWithManager(mgr)).To(Succeed())

		// Start the manager in a goroutine.
		go func() {
			defer GinkgoRecover()
			defer close(mgrDone)
			err := mgr.Start(mgrCtx)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Wait for the manager to be ready.
		Eventually(func() bool {
			return mgr.GetCache().WaitForCacheSync(mgrCtx)
		}).Should(BeTrue())
	}

	Context("when the TLS profile does not change", func() {
		It("should not trigger a shutdown", func() {
			// Start with the intermediate profile (same as what's configured).
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile)

			// Wait a bit and verify shutdown was not triggered.
			Consistently(shutdownCnt.Load).Should(Equal(int32(0)), "shutdown count should be 0 (no shutdown triggered)")
		})
	})

	Context("when the TLS profile changes", func() {
		It("should trigger a shutdown when MinTLSVersion changes", func() {
			// Start with the intermediate profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile)

			// Update the APIServer to use the Modern profile (which has TLS 1.3).
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify shutdown was triggered.
			Eventually(shutdownCnt.Load).Should(Equal(int32(1)), "shutdown count should be 1 (shutdown triggered)")
		})

		It("should trigger a shutdown when switching to custom profile", func() {
			// Start with the intermediate profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile)

			// Update the APIServer to use a custom profile.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
						MinTLSVersion: configv1.VersionTLS13,
					},
				},
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify shutdown was triggered.
			Eventually(shutdownCnt.Load).Should(Equal(int32(1)), "shutdown count should be 1 (shutdown triggered)")
		})

		It("should trigger a shutdown when switching from custom to predefined profile", func() {
			// Update the APIServer to use a custom profile first.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
						MinTLSVersion: configv1.VersionTLS13,
					},
				},
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Start with the custom profile.
			initialProfile, err := GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile)

			// Switch back to the intermediate profile.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify shutdown was triggered.
			Eventually(shutdownCnt.Load).Should(Equal(int32(1)), "shutdown count should be 1 (shutdown triggered)")
		})
	})

	Context("when the profile is nil initially", func() {
		It("should use the default profile and detect changes", func() {
			// Update APIServer to have nil profile.
			apiServer.Spec.TLSSecurityProfile = nil
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Start with the default (nil -> intermediate) profile.
			initialProfile, err := GetTLSProfileSpec(nil)
			Expect(err).NotTo(HaveOccurred())
			startManager(initialProfile)

			// Update the APIServer to use the Modern profile.
			apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}
			Expect(k8sClient.Update(ctx, apiServer)).To(Succeed())

			// Verify shutdown was triggered.
			Eventually(shutdownCnt.Load).Should(Equal(int32(1)), "shutdown count should be 1 (shutdown triggered)")
		})
	})
})
