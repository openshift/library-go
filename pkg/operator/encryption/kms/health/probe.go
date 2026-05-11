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

// healthzMaxBodyLen caps the plugin's Healthz body so a misbehaving
// plugin cannot push multi-MB strings into the OperatorCondition.Message
// on every tick.
const healthzMaxBodyLen = 200

// Probe never returns an error: failures classify into HealthStatus.Healthz
// so the Monitor loop stays flat.
type Probe struct {
	service kmsservice.Service
	timeout time.Duration
	now     func() time.Time
}

// NewProbe applies the timeout only when positive; 0 relies on ctx or
// the kmsv2 client's own deadline.
func NewProbe(service kmsservice.Service, timeout time.Duration) *Probe {
	return &Probe{
		service: service,
		timeout: timeout,
		now:     time.Now,
	}
}

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

// classifyHealthz truncates on a UTF-8-safe boundary: the proto allows
// arbitrary bytes, but Condition.Message must be valid UTF-8; naive
// byte-slicing could split a multi-byte rune.
func classifyHealthz(body string) Healthz {
	if body == string(HealthClassOK) {
		return Healthz{Class: HealthClassOK}
	}
	if len(body) > healthzMaxBodyLen {
		body = strings.ToValidUTF8(body[:healthzMaxBodyLen], "")
	}
	return Healthz{Class: HealthClassNotOK, Detail: body}
}

// status.Code returns codes.Unknown for non-gRPC errors and the real code
// for gRPC status errors, covering transport failures and deadlines without
// extra branching.
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
