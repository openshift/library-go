package creator

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/utils/clock"
)

type Serving struct {
	hostnamesFn   HostnamesFn
	keyPairGetter KeyPairGeneratorGetter
	lifetime      time.Duration
	signerGetter  SignerGetter
	clock         clock.PassiveClock
}

func NewServing(hostnamesFn HostnamesFn, keyPairGetter KeyPairGeneratorGetter, signerGetter SignerGetter, lifetime time.Duration) *Serving {
	return &Serving{
		hostnamesFn:   hostnamesFn,
		keyPairGetter: keyPairGetter,
		lifetime:      lifetime,
		signerGetter:  signerGetter,
		clock:         clock.RealClock{},
	}
}

func (c *Serving) CreateCertificate(ctx context.Context) (*crypto.TLSCertificateConfig, error) {
	signer, err := c.signerGetter.GetSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}

	kpg, err := c.keyPairGetter.GetKeyPairGenerator(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting key pair generator: %w", err)
	}

	return signer.NewServerCertificate(c.hostnamesFn(), kpg, crypto.WithLifetime(c.lifetime))
}
