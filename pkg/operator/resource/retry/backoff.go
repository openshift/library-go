package retry

import (
	"time"

	"github.com/cenkalti/backoff/v4"
)

// CuttableBackOff wraps another BackOff and subtracts a previously recorded
// duration from the next interval when CutNextBy has been called. This is
// useful when the previous operation already consumed wall-clock time (e.g.
// waiting for a request timeout) and adding the full backoff delay on top
// would be unnecessarily slow. If the cut exceeds the delegate's interval
// the result is clamped to zero.
//
// CuttableBackOff is not thread-safe as the core backoff library also isn't.
type CuttableBackOff struct {
	delegate backoff.BackOff
	cut      time.Duration
}

// NewCuttableBackOff creates a new CuttableBackOff wrapping delegate.
func NewCuttableBackOff(delegate backoff.BackOff) *CuttableBackOff {
	return &CuttableBackOff{delegate: delegate}
}

func (b *CuttableBackOff) NextBackOff() time.Duration {
	next := b.delegate.NextBackOff()
	if next == backoff.Stop {
		return backoff.Stop
	}

	cut := b.cut
	b.cut = 0
	if adjusted := next - cut; adjusted > 0 {
		return adjusted
	}
	return 0
}

func (b *CuttableBackOff) Reset() {
	b.cut = 0
	b.delegate.Reset()
}

// CutNextBy causes the next call to NextBackOff to subtract d from the
// delegate's interval. The value is consumed by a single NextBackOff call;
// multiple calls before NextBackOff overwrite the previous value.
func (b *CuttableBackOff) CutNextBy(d time.Duration) {
	b.cut = d
}
