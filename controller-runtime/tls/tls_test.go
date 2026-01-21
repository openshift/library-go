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
	"crypto/tls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
)

var _ = Describe("GetTLSProfileSpec", func() {
	Context("when profile is nil", func() {
		It("should return the default profile", func() {
			profile, err := GetTLSProfileSpec(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(profile).To(Equal(*configv1.TLSProfiles[DefaultTLSProfileType]))
		})
	})

	Context("when profile type is empty", func() {
		It("should return the default profile", func() {
			profile, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{})
			Expect(err).NotTo(HaveOccurred())
			Expect(profile).To(Equal(*configv1.TLSProfiles[DefaultTLSProfileType]))
		})
	})

	Context("when profile type is Intermediate", func() {
		It("should return the intermediate profile", func() {
			profile, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(profile).To(Equal(*configv1.TLSProfiles[configv1.TLSProfileIntermediateType]))
		})
	})

	Context("when profile type is Modern", func() {
		It("should return the modern profile", func() {
			profile, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(profile).To(Equal(*configv1.TLSProfiles[configv1.TLSProfileModernType]))
		})
	})

	Context("when profile type is Old", func() {
		It("should return the old profile", func() {
			profile, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(profile).To(Equal(*configv1.TLSProfiles[configv1.TLSProfileOldType]))
		})
	})

	Context("when profile type is Custom", func() {
		It("should return the custom profile spec", func() {
			customSpec := configv1.TLSProfileSpec{
				Ciphers:       []string{"ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305"},
				MinTLSVersion: configv1.VersionTLS13,
			}
			profile, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: customSpec,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(profile).To(Equal(customSpec))
		})

		It("should return an error when Custom field is nil", func() {
			_, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{
				Type:   configv1.TLSProfileCustomType,
				Custom: nil,
			})
			Expect(err).To(MatchError(ErrCustomProfileNil))
		})
	})

	Context("when profile type is unknown", func() {
		It("should return the default profile", func() {
			profile, err := GetTLSProfileSpec(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileType("UnknownType"),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(profile).To(Equal(*configv1.TLSProfiles[DefaultTLSProfileType]))
		})
	})
})

var _ = Describe("cipherCode", func() {
	Context("when cipher is an IANA name", func() {
		It("should return the correct cipher code", func() {
			Expect(cipherCode("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")).To(Equal(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
			Expect(cipherCode("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")).To(Equal(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384))
			Expect(cipherCode("TLS_AES_128_GCM_SHA256")).To(Equal(tls.TLS_AES_128_GCM_SHA256))
		})
	})

	Context("when cipher is an OpenSSL name", func() {
		It("should return the correct cipher code", func() {
			Expect(cipherCode("ECDHE-RSA-AES128-GCM-SHA256")).To(Equal(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
			Expect(cipherCode("ECDHE-ECDSA-AES256-GCM-SHA384")).To(Equal(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384))
			Expect(cipherCode("ECDHE-ECDSA-CHACHA20-POLY1305")).To(Equal(tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256))
		})
	})

	Context("when cipher is not supported", func() {
		It("should return 0", func() {
			Expect(cipherCode("UNSUPPORTED-CIPHER")).To(Equal(uint16(0)))
			Expect(cipherCode("")).To(Equal(uint16(0)))
			Expect(cipherCode("DHE-RSA-AES128-GCM-SHA256")).To(Equal(uint16(0))) // DHE not supported by Go
		})
	})
})

var _ = Describe("cipherCodes", func() {
	Context("when all ciphers are valid", func() {
		It("should return all cipher codes with no unsupported ciphers", func() {
			ciphers := []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"ECDHE-ECDSA-AES256-GCM-SHA384",
			}
			codes, unsupported := cipherCodes(ciphers)
			Expect(codes).To(HaveLen(2))
			Expect(codes).To(ContainElement(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
			Expect(codes).To(ContainElement(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384))
			Expect(unsupported).To(BeEmpty())
		})
	})

	Context("when some ciphers are invalid", func() {
		It("should return valid cipher codes and list unsupported ciphers", func() {
			ciphers := []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"UNSUPPORTED-CIPHER",
				"ECDHE-ECDSA-AES256-GCM-SHA384",
				"ANOTHER-INVALID",
			}
			codes, unsupported := cipherCodes(ciphers)
			Expect(codes).To(HaveLen(2))
			Expect(codes).To(ContainElement(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
			Expect(codes).To(ContainElement(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384))
			Expect(unsupported).To(ConsistOf("UNSUPPORTED-CIPHER", "ANOTHER-INVALID"))
		})
	})

	Context("when all ciphers are invalid", func() {
		It("should return empty codes and all ciphers as unsupported", func() {
			ciphers := []string{"INVALID-1", "INVALID-2"}
			codes, unsupported := cipherCodes(ciphers)
			Expect(codes).To(BeEmpty())
			Expect(unsupported).To(ConsistOf("INVALID-1", "INVALID-2"))
		})
	})

	Context("when cipher list is empty", func() {
		It("should return empty slices", func() {
			codes, unsupported := cipherCodes([]string{})
			Expect(codes).To(BeEmpty())
			Expect(unsupported).To(BeEmpty())
		})
	})

	Context("when cipher list is nil", func() {
		It("should return empty slices", func() {
			codes, unsupported := cipherCodes(nil)
			Expect(codes).To(BeEmpty())
			Expect(unsupported).To(BeEmpty())
		})
	})
})

var _ = Describe("NewTLSConfigFromProfile", func() {
	Context("when MinTLSVersion is TLS 1.2", func() {
		It("should set MinVersion and CipherSuites", func() {
			profile := configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS12,
				Ciphers: []string{
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"ECDHE-ECDSA-AES256-GCM-SHA384",
				},
			}

			tlsConfigFn, unsupported := NewTLSConfigFromProfile(profile)
			Expect(unsupported).To(BeEmpty())

			tlsConf := &tls.Config{}
			tlsConfigFn(tlsConf)

			Expect(tlsConf.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(tlsConf.CipherSuites).To(HaveLen(2))
			Expect(tlsConf.CipherSuites).To(ContainElement(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
			Expect(tlsConf.CipherSuites).To(ContainElement(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384))
		})
	})

	Context("when MinTLSVersion is TLS 1.3", func() {
		It("should set MinVersion but NOT set CipherSuites (TLS 1.3 ciphers are not configurable)", func() {
			profile := configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS13,
				Ciphers: []string{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
				},
			}

			tlsConfigFn, unsupported := NewTLSConfigFromProfile(profile)
			Expect(unsupported).To(BeEmpty())

			tlsConf := &tls.Config{}
			tlsConfigFn(tlsConf)

			Expect(tlsConf.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			// CipherSuites should NOT be set for TLS 1.3
			Expect(tlsConf.CipherSuites).To(BeNil())
		})
	})

	Context("when profile contains unsupported ciphers", func() {
		It("should return unsupported ciphers list", func() {
			profile := configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS12,
				Ciphers: []string{
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"DHE-RSA-AES128-GCM-SHA256", // Not supported by Go
					"INVALID-CIPHER",
				},
			}

			tlsConfigFn, unsupported := NewTLSConfigFromProfile(profile)
			Expect(unsupported).To(ConsistOf("DHE-RSA-AES128-GCM-SHA256", "INVALID-CIPHER"))

			tlsConf := &tls.Config{}
			tlsConfigFn(tlsConf)

			Expect(tlsConf.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(tlsConf.CipherSuites).To(HaveLen(1))
			Expect(tlsConf.CipherSuites).To(ContainElement(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
		})
	})

	Context("when using the Intermediate profile", func() {
		It("should configure TLS correctly", func() {
			profile := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]

			tlsConfigFn, unsupported := NewTLSConfigFromProfile(profile)

			tlsConf := &tls.Config{}
			tlsConfigFn(tlsConf)

			Expect(tlsConf.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			// Intermediate profile uses TLS 1.2, so CipherSuites should be set
			Expect(tlsConf.CipherSuites).NotTo(BeEmpty())
			// Some ciphers in the Intermediate profile may not be supported by Go
			// (e.g., DHE ciphers), so we just check that we have some ciphers
			Expect(len(tlsConf.CipherSuites) + len(unsupported)).To(Equal(len(profile.Ciphers)))
		})
	})

	Context("when using the Modern profile", func() {
		It("should configure TLS correctly with TLS 1.3", func() {
			profile := *configv1.TLSProfiles[configv1.TLSProfileModernType]

			tlsConfigFn, _ := NewTLSConfigFromProfile(profile)

			tlsConf := &tls.Config{}
			tlsConfigFn(tlsConf)

			Expect(tlsConf.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			// Modern profile uses TLS 1.3, so CipherSuites should NOT be set
			Expect(tlsConf.CipherSuites).To(BeNil())
		})
	})
})
