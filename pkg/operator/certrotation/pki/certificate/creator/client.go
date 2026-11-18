package creator

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/utils/clock"
)

type Client struct {
	userInfo      user.Info
	keyPairGetter KeyPairGeneratorGetter
	lifetime      time.Duration
	signerGetter  SignerGetter
	clock         clock.PassiveClock
}

func NewClient(userInfo user.Info, keyPairGetter KeyPairGeneratorGetter, signerGetter SignerGetter, lifetime time.Duration) *Client {
	return &Client{
		userInfo:      userInfo,
		keyPairGetter: keyPairGetter,
		lifetime:      lifetime,
		signerGetter:  signerGetter,
		clock:         clock.RealClock{},
	}
}

func (c *Client) CreateCertificate(ctx context.Context) (*crypto.TLSCertificateConfig, error) {
	signer, err := c.signerGetter.GetSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}

	kpg, err := c.keyPairGetter.GetKeyPairGenerator()
	if err != nil {
		return nil, fmt.Errorf("getting key pair generator: %w", err)
	}

	return signer.NewClientCertificate(c.userInfo, kpg, crypto.WithLifetime(c.lifetime))
}
