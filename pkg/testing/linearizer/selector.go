package linearizer

import "math/rand"

// internal
// selects one from a list of waiting actors
type selector interface {
	// returns the index of the actor from the waiting list
	// that should be unblocked next
	pick([]*waiter) int

	// returns true if there are more iterations available
	more() bool
}

type fifo struct{}

func (fifo) pick(w []*waiter) int { return 0 }
func (fifo) more() bool           { return true }

type lifo struct{}

func (lifo) pick(w []*waiter) int { return len(w) - 1 }
func (lifo) more() bool           { return true }

type randomizer struct {
	r *rand.Rand
}

func (r randomizer) pick(w []*waiter) int {
	if len(w) <= 1 {
		return len(w) - 1
	}
	return r.r.Intn(len(w))
}
func (f randomizer) more() bool { return true }
