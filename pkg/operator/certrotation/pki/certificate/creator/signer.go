package creator

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/utils/clock"
)

type IntermediateSigner struct {
	name          string
	keyPairGetter KeyPairGeneratorGetter
	lifetime      time.Duration
	signerGetter  SignerGetter
	clock         clock.PassiveClock
}

func NewIntermediateSigner(name string, keyPairGetter KeyPairGeneratorGetter, signerGetter SignerGetter, lifetime time.Duration) *IntermediateSigner {
	return &IntermediateSigner{
		name:          name,
		keyPairGetter: keyPairGetter,
		lifetime:      lifetime,
		signerGetter:  signerGetter,
		clock:         clock.RealClock{},
	}
}

func (c *IntermediateSigner) CreateCertificate(ctx context.Context) (*crypto.TLSCertificateConfig, error) {
	now := c.clock.Now()
	name := fmt.Sprintf("%s@%d", c.name, now.Unix())

	signer, err := c.signerGetter.GetSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}

	kpg, err := c.keyPairGetter.GetKeyPairGenerator(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting key pair generator: %w", err)
	}

	return crypto.NewSigningCertificate(name, kpg, crypto.WithLifetime(c.lifetime), crypto.WithSigner(signer))
}

type SelfSignedSigner struct {
	name          string
	keyPairGetter KeyPairGeneratorGetter
	lifetime      time.Duration
	clock         clock.PassiveClock
}

func NewSelfSignedSigner(name string, keyPairGetter KeyPairGeneratorGetter, lifetime time.Duration) *SelfSignedSigner {
	return &SelfSignedSigner{
		name:          name,
		keyPairGetter: keyPairGetter,
		lifetime:      lifetime,
		clock:         clock.RealClock{},
	}
}

func (c *SelfSignedSigner) CreateCertificate(ctx context.Context) (*crypto.TLSCertificateConfig, error) {
	now := c.clock.Now()
	name := fmt.Sprintf("%s@%d", c.name, now.Unix())

	// TODO: if signer is specified, do cross-signing.

	kpg, err := c.keyPairGetter.GetKeyPairGenerator(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting key pair generator: %w", err)
	}

	return crypto.NewSigningCertificate(name, kpg, crypto.WithLifetime(c.lifetime))
}
