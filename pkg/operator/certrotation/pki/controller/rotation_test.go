package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation/pki/certificate/creator"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
)

func TestCertificateRotationControllerSync(t *testing.T) {
	type testcase struct {
		name               string
		certificateCreator CertificateCreator
		metadataFn         CertificateRotationMetadataFn
		rotationFn         CertificateRotationRotationFn
		validateActions    func(*testing.T, []clienttesting.Action)
		initialSecret      *corev1.Secret
		setupReactorFn     func(*fake.Clientset)
		lister             corev1listers.SecretLister
		expectedErr        error
	}

	testcases := []testcase{
		{
			name: "no existing resource, self-signed signing certificate creator successfully creates a self-signed signing certificate, successfully creates desired self-signed signing certificate secret",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },

			// rotationFn should never be called in this scenario, make it nil so test panics if it is called.
			rotationFn:    nil,
			initialSecret: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("create", "secrets") {
					t.Fatalf("expected action to be a create on secrets but got %v", action)
				}

				createAction, ok := action.(clienttesting.CreateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.CreateAction but got %T", action)
				}

				obj := createAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "certificaterotationcontroller-test", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "no existing resource, self-signed signing certificate creator successfully creates a self-signed signing certificate, successfully creates desired self-signed signing certificate secret with metadata",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool {
				if s.Annotations == nil {
					s.Annotations = map[string]string{}
				}

				s.Annotations["openshift.io/certificate-rotation-controller-test"] = "custom-annotation"
				return true
			},

			// rotationFn should never be called in this scenario, make it nil so test panics if it is called.
			rotationFn:    nil,
			initialSecret: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("create", "secrets") {
					t.Fatalf("expected action to be a create on secrets but got %v", action)
				}

				createAction, ok := action.(clienttesting.CreateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.CreateAction but got %T", action)
				}

				obj := createAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				customAnnotation, ok := secret.Annotations["openshift.io/certificate-rotation-controller-test"]
				if !ok {
					t.Fatalf("expected secret to contain annotation %q but it did not", "openshift.io/certificate-rotation-controller-test")
				}

				if customAnnotation != "custom-annotation" {
					t.Fatalf("secret annotation %q expected to have value %q but has %q", "openshift.io/certificate-rotation-controller-test", "custom-annotation", customAnnotation)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "certificaterotationcontroller-test", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "no existing resource, self-signed signing certificate creator fails to create a self-signed signing certificate, error",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					err: errors.New("boom"),
				},
				time.Hour,
			),
			metadataFn:    nil,
			rotationFn:    nil,
			initialSecret: nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 0 {
					t.Fatalf("expected no actions to occur but got %d", len(a))
				}
			},
			expectedErr: errors.New("creating certificate and key bytes: creating certificate: getting key pair generator: boom"),
		},
		{
			name: "no existing resource, self-signed signing certificate successfully creates a self-signed signing certificate, fails to create secret, error",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn:    nil,
			rotationFn:    nil,
			initialSecret: nil,
			setupReactorFn: func(c *fake.Clientset) {
				c.PrependReactor("create", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					createAction, ok := action.(clienttesting.CreateAction)
					if !ok {
						return false, nil, nil
					}

					if obj, ok := createAction.GetObject().(*corev1.Secret); ok && obj.Namespace == "test" && obj.Name == "certificate" {
						return true, nil, apierrors.NewBadRequest("boom")
					}
					return false, nil, nil
				})
			},
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				// Checking the error return is sufficient
				return
			},
			expectedErr: errors.New("creating secret \"test/certificate\": boom"),
		},
		{
			name: "existing resource, rotation required, self-signed signing certificate creator successfully creates a self-signed signing certificate, successfully updates desired self-signed signing certificate secret",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return true, "always rotate", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "secrets") {
					t.Fatalf("expected action to be an update on secrets but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				obj := updateAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "certificaterotationcontroller-test", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "existing resource, rotation required, self-signed signing certificate creator fails to create a self-signed signing certificate, no attempt to update secret, error",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					err: errors.New("boom"),
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return true, "always rotate", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 0 {
					t.Fatalf("expected no actions to occur but got %d", len(a))
				}
			},
			expectedErr: errors.New("creating certificate and key bytes: creating certificate: getting key pair generator: boom"),
		},
		{
			name: "existing resource, rotation required, self-signed signing certificate creator successfully creates a self-signed signing certificate, fail to update secret, error",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return true, "always rotate", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				// error check is sufficient
				return
			},
			setupReactorFn: func(c *fake.Clientset) {
				c.PrependReactor("update", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					updateAction, ok := action.(clienttesting.UpdateAction)
					if !ok {
						return false, nil, nil
					}

					if obj, ok := updateAction.GetObject().(*corev1.Secret); ok && obj.Namespace == "test" && obj.Name == "certificate" {
						return true, nil, apierrors.NewBadRequest("boom")
					}
					return false, nil, nil
				})
			},
			expectedErr: errors.New("updating secret \"test/certificate\": boom"),
		},
		{
			name: "existing resource, rotation returns error, certificateCreator not called, no attempt to update secret, error",
			// setting this to nil will cause a panic if it attempts to be called.
			certificateCreator: nil,
			metadataFn:         func(s *corev1.Secret) bool { return false },
			rotationFn:         func(s *corev1.Secret) (bool, string, error) { return false, "", errors.New("boom") },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 0 {
					t.Fatalf("expected no actions to occur but got %d", len(a))
				}
			},
			expectedErr: errors.New("determining if secret \"test/certificate\" needs rotation: boom"),
		},
		{
			name: "existing resource, no rotation required, metadata update required, existing secret metadata updated",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool {
				if s.Annotations == nil {
					s.Annotations = map[string]string{}
				}
				s.Annotations["openshift.io/certificate-rotation-controller-test"] = "custom-annotation"
				return true
			},
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return false, "", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "secrets") {
					t.Fatalf("expected action to be an update on secrets but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				obj := updateAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				customAnnotation, ok := secret.Annotations["openshift.io/certificate-rotation-controller-test"]
				if !ok {
					t.Fatalf("expected secret to contain annotation %q but it did not", "openshift.io/certificate-rotation-controller-test")
				}

				if customAnnotation != "custom-annotation" {
					t.Fatalf("secret annotation %q expected to have value %q but has %q", "openshift.io/certificate-rotation-controller-test", "custom-annotation", customAnnotation)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				// no rotation means that this should still be the initial secret contents
				if !strings.HasPrefix(leaf.Subject.CommonName, "initial") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "initial", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "existing resource, no rotation required, metadata update required, fail to update secret, error",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool {
				if s.Annotations == nil {
					s.Annotations = map[string]string{}
				}
				s.Annotations["openshift.io/certificate-rotation-controller-test"] = "custom-annotation"
				return true
			},
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return false, "", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				// error check is sufficient
				return
			},
			setupReactorFn: func(c *fake.Clientset) {
				c.PrependReactor("update", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					updateAction, ok := action.(clienttesting.UpdateAction)
					if !ok {
						return false, nil, nil
					}

					if obj, ok := updateAction.GetObject().(*corev1.Secret); ok && obj.Namespace == "test" && obj.Name == "certificate" {
						return true, nil, apierrors.NewBadRequest("boom")
					}
					return false, nil, nil
				})
			},
			expectedErr: errors.New("updating secret \"test/certificate\": boom"),
		},
		{
			name: "existing resource, no rotation required, no metadata update required, no actions taken",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return false, "", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) > 0 {
					t.Fatalf("expected no actions to be taken but got %d: %v", len(a), a)
				}
			},
		},
		{
			name: "existing resource, missing data, no rotation required, no metadata update required, rotation happens due to missing contents",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return false, "", nil },
			initialSecret: func() *corev1.Secret {
				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "secrets") {
					t.Fatalf("expected action to be an update on secrets but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				obj := updateAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "certificaterotationcontroller-test", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "existing resource, missing certificate key, no rotation required, no metadata update required, rotation happens due to missing contents",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return false, "", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				_, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "secrets") {
					t.Fatalf("expected action to be an update on secrets but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				obj := updateAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "certificaterotationcontroller-test", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "existing resource, missing private key key, no rotation required, no metadata update required, rotation happens due to missing contents",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return false, "", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, _, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "secrets") {
					t.Fatalf("expected action to be an update on secrets but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				obj := updateAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "certificaterotationcontroller-test", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "existing resource, certificate key exists but is empty, no rotation required, no metadata update required, rotation happens due to missing contents",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return false, "", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				_, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": []byte(""),
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "secrets") {
					t.Fatalf("expected action to be an update on secrets but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				obj := updateAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "certificaterotationcontroller-test", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "existing resource, private key key exists but is empty, no rotation required, no metadata update required, rotation happens due to missing contents",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool { return false },
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return false, "", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, _, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": []byte(""),
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "secrets") {
					t.Fatalf("expected action to be an update on secrets but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				obj := updateAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				if secret.Data == nil {
					t.Fatal("expected secret to contain data but it did not")
				}

				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				keyBytes, ok := secret.Data["tls.key"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.key' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
				if err != nil {
					t.Fatalf("could not load certificate data from secret certificate and key bytes: %v", err)
				}

				leaf := ca.Config.Certs[0]
				err = leaf.CheckSignatureFrom(leaf)
				if err != nil {
					t.Fatalf("leaf certificate could not verify its own signature was from itself, meaning it is not self-signed: %v", err)
				}

				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("leaf certificate subject common name should have prefix %q but did not: %q", "certificaterotationcontroller-test", leaf.Subject.CommonName)
				}
			},
		},
		{
			name: "existing resource, rotation required and metadata update required, both are applied",
			certificateCreator: creator.NewSelfSignedSigner(
				"certificaterotationcontroller-test",
				&mockKeyPairGeneratorGetter{
					kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
				},
				time.Hour,
			),
			metadataFn: func(s *corev1.Secret) bool {
				if s.Annotations == nil {
					s.Annotations = map[string]string{}
				}
				s.Annotations["test.io/rotated"] = "true"
				return true
			},
			rotationFn: func(s *corev1.Secret) (bool, string, error) { return true, "both changes needed", nil },
			initialSecret: func() *corev1.Secret {
				cfg, err := crypto.NewSigningCertificate("initial", crypto.RSAKeyPairGenerator{Bits: 2048})
				if err != nil {
					t.Fatalf("creating initial signing certificate: %v", err)
				}

				certBytes, keyBytes, err := cfg.GetPEMBytes()
				if err != nil {
					t.Fatalf("getting initial signing certificate PEM bytes: %v", err)
				}

				return &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      "certificate",
						Namespace: "test",
					},
					Data: map[string][]byte{
						"tls.crt": certBytes,
						"tls.key": keyBytes,
					},
				}
			}(),
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				if len(a) != 1 {
					t.Fatalf("expected exactly 1 action to occur but got %d", len(a))
				}

				action := a[0]
				if !action.Matches("update", "secrets") {
					t.Fatalf("expected action to be an update on secrets but got %v", action)
				}

				updateAction, ok := action.(clienttesting.UpdateAction)
				if !ok {
					t.Fatalf("expected action to be a clienttesting.UpdateAction but got %T", action)
				}

				obj := updateAction.GetObject()

				secret, ok := obj.(*corev1.Secret)
				if !ok {
					t.Fatalf("expected action to be on object of type *corev1.Secret but got %T", obj)
				}

				// Verify rotation happened — cert should be new (different CN)
				certBytes, ok := secret.Data["tls.crt"]
				if !ok {
					t.Fatal("expected secret to contain key 'tls.crt' but it did not")
				}

				ca, err := crypto.GetCAFromBytes(certBytes, secret.Data["tls.key"])
				if err != nil {
					t.Fatalf("could not load certificate data: %v", err)
				}

				leaf := ca.Config.Certs[0]
				if !strings.HasPrefix(leaf.Subject.CommonName, "certificaterotationcontroller-test") {
					t.Fatalf("expected rotated cert to have new CN but got %q", leaf.Subject.CommonName)
				}

				// Verify metadata updated
				annotation, ok := secret.Annotations["test.io/rotated"]
				if !ok {
					t.Fatal("expected secret to contain annotation 'test.io/rotated' but it did not")
				}

				if annotation != "true" {
					t.Fatalf("expected annotation to have value 'true' but got %q", annotation)
				}
			},
		},
		{
			name:               "fail to get existing secret, error",
			certificateCreator: nil,
			metadataFn:         nil,
			rotationFn:         nil,
			initialSecret:      nil,
			validateActions: func(t *testing.T, a []clienttesting.Action) {
				// Checking the error return is sufficient
				return
			},
			lister:      &failingSecretLister{err: errors.New("boom")},
			expectedErr: errors.New("getting secret \"test/certificate\": boom"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			if tc.initialSecret != nil {
				fakeClient = fake.NewSimpleClientset(tc.initialSecret)
			}

			if tc.setupReactorFn != nil {
				tc.setupReactorFn(fakeClient)
			}

			informerFactory := informers.NewSharedInformerFactory(fakeClient, 0)

			secretInformer := informerFactory.Core().V1().Secrets()
			if tc.initialSecret != nil {
				secretInformer.Informer().GetIndexer().Add(tc.initialSecret)
			}

			lister := secretInformer.Lister()
			if tc.lister != nil {
				lister = tc.lister
			}

			eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})

			rotationController := &CertificateRotation{
				namespace: "test",
				name:      "certificate",

				client:        fakeClient.CoreV1(),
				lister:        lister,
				eventRecorder: eventRecorder,

				certificateCreator: tc.certificateCreator,
				metadataFn:         tc.metadataFn,
				rotationFn:         tc.rotationFn,
			}

			err := rotationController.Sync(t.Context(), factory.NewSyncContext("test", eventRecorder))
			if err != nil {
				if tc.expectedErr != nil && err.Error() == tc.expectedErr.Error() {
					tc.validateActions(t, fakeClient.Actions())
					return
				}

				t.Fatalf("expected error %q but got %q", tc.expectedErr.Error(), err.Error())
			}

			if tc.expectedErr != nil {
				t.Fatalf("expected error %q but got none", tc.expectedErr.Error())
			}

			tc.validateActions(t, fakeClient.Actions())
		})
	}
}

type mockKeyPairGeneratorGetter struct {
	kpg crypto.KeyPairGenerator
	err error
}

func (m *mockKeyPairGeneratorGetter) GetKeyPairGenerator(_ context.Context) (crypto.KeyPairGenerator, error) {
	return m.kpg, m.err
}

type failingSecretLister struct {
	err error
}

func (fsl *failingSecretLister) List(_ labels.Selector) ([]*corev1.Secret, error) {
	return nil, fsl.err
}

func (fsl *failingSecretLister) Secrets(_ string) corev1listers.SecretNamespaceLister {
	return fsl
}

func (fsl *failingSecretLister) Get(_ string) (*corev1.Secret, error) {
	return nil, fsl.err
}
