package certrotation

import (
	"errors"

	"github.com/openshift/library-go/pkg/pki"
)

// PKI selects how key material and certificate templates are produced. The
// zero value is invalid: every caller must choose, making the feature-gate
// decision explicit at the call site instead of a nil-able struct field.
type PKI struct {
	mode     pkiMode
	provider pki.ConfigProvider
}

type pkiMode int

const (
	pkiModeInvalid pkiMode = iota
	pkiModeLegacy
	pkiModeConfigurable
)

// LegacyPKI reproduces v1's pre-ConfigurablePKI certificate generation
// exactly: crypto.MakeSelfSignedCAConfigForDuration, MakeServerCertForDuration
// and their siblings. It exists for the feature-gate-off case and is removed
// once ConfigurablePKI is GA everywhere.
func LegacyPKI() PKI {
	return PKI{mode: pkiModeLegacy}
}

// ConfigurablePKI resolves key configuration through the PKI API. The
// provider must be non-nil. A provider error, including a missing PKI
// resource, fails the sync with ErrPKIConfig; there is never a silent
// fallback to defaults.
func ConfigurablePKI(provider pki.ConfigProvider) PKI {
	return PKI{mode: pkiModeConfigurable, provider: provider}
}

// ErrPKIProviderRequired is returned by validation when ConfigurablePKI is
// constructed without a provider.
var ErrPKIProviderRequired = errors.New("ConfigurablePKI requires a non-nil pki.ConfigProvider")

func (p PKI) validate() error {
	switch p.mode {
	case pkiModeLegacy:
		return nil
	case pkiModeConfigurable:
		if p.provider == nil {
			return ErrPKIProviderRequired
		}
		return nil
	default:
		return ErrPKIRequired
	}
}
