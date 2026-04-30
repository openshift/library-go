package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"google.golang.org/grpc/status"
	kmsservice "k8s.io/kms/pkg/service"
)

// healthzMaxBodyLen caps the plugin's Healthz body. Without it a
// misbehaving plugin could push multi-MB strings into our ConfigMap on
// every tick.
const healthzMaxBodyLen = 200

// Probe never returns an error; failures are classified into
// HealthStatus.Healthz so the Monitor loop stays flat.
type Probe struct {
	service kmsservice.Service
	timeout time.Duration
	now     func() time.Time
}

// NewProbe wraps the per-probe Status RPC with timeout if positive; 0
// relies solely on ctx (or the kmsv2 client's own deadline).
func NewProbe(service kmsservice.Service, timeout time.Duration) *Probe {
	return &Probe{
		service: service,
		timeout: timeout,
		now:     time.Now,
	}
}

// Probe blocks until Status returns or ctx / the per-probe timeout fires.
func (p *Probe) Probe(ctx context.Context) HealthStatus {
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}
	resp, err := p.service.Status(ctx)
	timestamp := p.now()
	if err != nil {
		return HealthStatus{
			Healthz:   classifyRPCError(err),
			Timestamp: timestamp,
		}
	}
	return HealthStatus{
		Healthz:   classifyHealthz(resp.Healthz),
		KeyIDHash: hashKeyID(resp.KeyID),
		Timestamp: timestamp,
	}
}

// classifyHealthz truncates overlong bodies on a UTF-8-safe boundary:
// the proto permits free-form text, ConfigMap.Data must be valid UTF-8,
// and naive byte-slicing at healthzMaxBodyLen could split a multi-byte
// rune. ToValidUTF8 drops any partial sequence at the cut.
func classifyHealthz(body string) Healthz {
	if body == string(HealthClassOK) {
		return Healthz{Class: HealthClassOK}
	}
	if len(body) > healthzMaxBodyLen {
		body = strings.ToValidUTF8(body[:healthzMaxBodyLen], "")
	}
	return Healthz{Class: HealthClassNotOK, Detail: body}
}

// classifyRPCError uses status.Code, which returns codes.Unknown for
// non-gRPC errors and the real code for gRPC status errors. Covers
// transport failures and deadline expirations without extra branching.
func classifyRPCError(err error) Healthz {
	return Healthz{
		Class:  HealthClassRPCError,
		Detail: status.Code(err).String(),
	}
}

func hashKeyID(keyID string) string {
	if keyID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(keyID))
	return hex.EncodeToString(sum[:])
}
