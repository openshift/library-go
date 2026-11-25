package creator

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/utils/clock"
)

type HostnamesFn func() sets.Set[string]

type Peer struct {
	hostnamesFn   HostnamesFn
	userInfo      user.Info
	keyPairGetter KeyPairGeneratorGetter
	lifetime      time.Duration
	signerGetter  SignerGetter
	clock         clock.PassiveClock
}

func NewPeer(hostnamesFn HostnamesFn, userInfo user.Info, keyPairGetter KeyPairGeneratorGetter, signerGetter SignerGetter, lifetime time.Duration) *Peer {
	return &Peer{
		hostnamesFn:   hostnamesFn,
		userInfo:      userInfo,
		keyPairGetter: keyPairGetter,
		lifetime:      lifetime,
		signerGetter:  signerGetter,
		clock:         clock.RealClock{},
	}
}

func (c *Peer) CreateCertificate(ctx context.Context) (*crypto.TLSCertificateConfig, error) {
	signer, err := c.signerGetter.GetSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}

	kpg, err := c.keyPairGetter.GetKeyPairGenerator(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting key pair generator: %w", err)
	}

	return signer.NewPeerCertificate(c.hostnamesFn(), c.userInfo, kpg, crypto.WithLifetime(c.lifetime), crypto.WithNowFunc(c.clock.Now))
}
