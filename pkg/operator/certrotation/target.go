package certrotation

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/openshift/library-go/pkg/certs"
	"github.com/openshift/library-go/pkg/crypto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TargetCertKeyPairConfig holds the configuration for a target certificate key pair.
type TargetCertKeyPairConfig struct {
	// Namespace is the namespace of the Secret.
	Namespace string
	// Name is the name of the Secret.
	Name string
	// CertificateName is the logical name of this certificate for PKI profile resolution.
	// When a PKI profile provider is configured on the controller, this name is used to
	// look up the key algorithm and other certificate parameters from the cluster PKI profile.
	CertificateName string
	// Validity is the duration from time.Now() until the certificate expires. If RefreshOnlyWhenExpired
	// is false, the key and certificate is rotated when 80% of validity is reached.
	Validity time.Duration
	// Refresh is the duration after certificate creation when it is rotated at the latest. It is ignored
	// if RefreshOnlyWhenExpired is true, or if Refresh > Validity.
	// Refresh is ignored until the signing CA at least 10% in its life-time to ensure it is deployed
	// through-out the cluster.
	Refresh time.Duration
	// RefreshOnlyWhenExpired set to true means to ignore 80% of validity and the Refresh duration for rotation,
	// but only rotate when the certificate expires. This is useful for auto-recovery when we want to enforce
	// rotation on expiration only, but not interfere with the ordinary rotation controller.
	RefreshOnlyWhenExpired bool

	// Owner is an optional reference to add to the secret that this rotator creates. Use this when downstream
	// consumers of the certificate need to be aware of changes to the object.
	// WARNING: be careful when using this option, as deletion of the owning object will cascade into deletion
	// of the certificate. If the lifetime of the owning object is not a superset of the lifetime in which the
	// certificate is used, early deletion will be catastrophic.
	Owner *metav1.OwnerReference

	// AdditionalAnnotations is a collection of annotations set for the secret
	AdditionalAnnotations AdditionalAnnotations

	// CertConfig specifies the type of certificate to create.
	CertConfig TargetCertConfig
}

// TargetCertConfig is a sealed interface for target certificate configuration.
// Implementations: ClientCertConfig, ServingCertConfig, SignerCertConfig.
type TargetCertConfig interface {
	targetCertConfig()
}

// ClientCertConfig configures a client certificate.
type ClientCertConfig struct {
	UserInfo user.Info
}

func (ClientCertConfig) targetCertConfig() {}

// ServingCertConfig configures a serving certificate.
type ServingCertConfig struct {
	Hostnames              func() []string
	HostnamesChanged       <-chan struct{}
	CertificateExtensionFn []crypto.CertificateExtensionFunc
}

func (ServingCertConfig) targetCertConfig() {}

// SignerCertConfig configures an intermediate signer certificate.
type SignerCertConfig struct {
	SignerName string
}

func (SignerCertConfig) targetCertConfig() {}

func needNewTargetCertKeyPair(secret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration, refreshOnlyWhenExpired, creationRequired bool, hostnames func() []string) string {
	if creationRequired {
		return "secret doesn't exist"
	}

	annotations := secret.Annotations
	if reason := needNewTargetCertKeyPairForTime(annotations, signer, refresh, refreshOnlyWhenExpired); len(reason) > 0 {
		return reason
	}

	// Exit early if we're only refreshing when expired and the certificate does not need an update
	if refreshOnlyWhenExpired {
		return ""
	}

	// check the signer common name against all the common names in our ca bundle so we don't refresh early
	signerCommonName := annotations[CertificateIssuer]
	if len(signerCommonName) == 0 {
		return "missing issuer name"
	}
	for _, caCert := range caBundleCerts {
		if signerCommonName == caCert.Subject.CommonName {
			// Signer is in the CA bundle. Check hostnames if applicable.
			if hostnames != nil {
				return missingHostnames(secret.Annotations, hostnames)
			}
			return ""
		}
	}

	return fmt.Sprintf("issuer %q, not in ca bundle:\n%s", signerCommonName, certs.CertificateBundleToString(caBundleCerts))
}

// needNewTargetCertKeyPairForTime returns true when
//  1. when notAfter or notBefore is missing in the annotation
//  2. when notAfter or notBefore is malformed
//  3. when now is after the notAfter
//  4. when now is after notAfter+refresh AND the signer has been valid
//     for more than 5% of the "extra" time we renew the target
//
// in other words, we rotate if
//
// our old CA is gone from the bundle (then we are pretty late to the renewal party)
// or the cert expired (then we are also pretty late)
// or we are over the renewal percentage of the validity, but only if the new CA at least 10% into its age.
// Maybe worth a go doc.
//
// So in general we need to see a signing CA at least aged 10% within 1-percentage of the cert validity.
//
// Hence, if the CAs are rotated too fast (like CA percentage around 10% or smaller), we will not hit the time to make use of the CA. Or if the cert renewal percentage is at 90%, there is not much time either.
//
// So with a cert percentage of 75% and equally long CA and cert validities at the worst case we start at 85% of the cert to renew, trying again every minute.
func needNewTargetCertKeyPairForTime(annotations map[string]string, signer *crypto.CA, refresh time.Duration, refreshOnlyWhenExpired bool) string {
	notBefore, notAfter, reason := getValidityFromAnnotations(annotations)
	if len(reason) > 0 {
		return reason
	}

	// Is cert expired?
	if time.Now().After(notAfter) {
		return "already expired"
	}

	if refreshOnlyWhenExpired {
		return ""
	}

	// Are we at 80% of validity?
	validity := notAfter.Sub(notBefore)
	at80Percent := notAfter.Add(-validity / 5)
	if time.Now().After(at80Percent) {
		return fmt.Sprintf("past refresh time (80%% of validity): %v", at80Percent)
	}

	// If Certificate is past its refresh time, we may have action to take. We only do this if the signer is old enough.
	refreshTime := notBefore.Add(refresh)
	if time.Now().After(refreshTime) {
		// make sure the signer has been valid for more than 10% of the target's refresh time.
		timeToWaitForTrustRotation := refresh / 10
		if time.Now().After(signer.Config.Certs[0].NotBefore.Add(time.Duration(timeToWaitForTrustRotation))) {
			return fmt.Sprintf("past its refresh time %v", refreshTime)
		}
	}

	return ""
}

func missingHostnames(annotations map[string]string, hostnames func() []string) string {
	existingHostnames := sets.New(strings.Split(annotations[CertificateHostnames], ",")...)
	requiredHostnames := sets.New(hostnames()...)
	if !existingHostnames.Equal(requiredHostnames) {
		existingNotRequired := existingHostnames.Difference(requiredHostnames)
		requiredNotExisting := requiredHostnames.Difference(existingHostnames)
		return fmt.Sprintf("%q are existing and not required, %q are required and not existing", strings.Join(sets.List(existingNotRequired), ","), strings.Join(sets.List(requiredNotExisting), ","))
	}

	return ""
}
