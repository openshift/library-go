package linearizer

import (
	"sort"
)

// Each of the concurrently running controllers id assigned a unique actor
type Actor interface {
	ID() int

	// Each API call is prepended with Wait so the invocation can be
	// linearized across multiple concurrent actors
	Wait(op string) <-chan struct{}

	// Must be invoked as soon as an actor is about to exit a goroutine
	Exit()
}

type actor struct {
	id  int
	run *iteration
}

func (a actor) ID() int { return a.id }

func (a actor) Exit() {
	a.run.dispatch(nil)
}

func (a actor) Wait(op string) <-chan struct{} {
	ch := make(chan struct{})
	a.run.dispatch(&waiter{actorID: a.id, ch: ch, op: op})
	return ch
}

type ByActorID []*waiter

func (a ByActorID) Len() int           { return len(a) }
func (a ByActorID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByActorID) Less(i, j int) bool { return a[i].actorID < a[j].actorID }
func (a ByActorID) find(actorID int) int {
	for i := range a {
		if a[i].actorID == actorID {
			return i
		}
	}
	return -1
}

func sortByIActorID(w []*waiter) {
	if len(w) <= 1 {
		return
	}
	if len(w) == 2 {
		if w[0].actorID > w[1].actorID {
			w[0], w[1] = w[1], w[0]
		}
		return
	}
	// TODO: optimize
	sort.Sort(ByActorID(w))
}
