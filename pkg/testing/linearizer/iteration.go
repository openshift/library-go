package linearizer

import (
	"fmt"
	"sync"
	"sync/atomic"
)

func label(actorID int) string { return fmt.Sprintf("actor-%d", actorID) }

// describes an actor waiting to be unblocked
type waiter struct {
	actorID int
	op      string
	ch      chan struct{}
}

type iteration struct {
	// number of actors active at any moment
	active   atomic.Int64
	actors   map[string]*actor
	lock     sync.Mutex
	selector selector
	// list of actors waiting to resume execution
	waiters  []*waiter
	sequence string
}

func (i *iteration) Sequence() string {
	return i.sequence
}

func (i *iteration) GetMyActor() Actor {
	i.lock.Lock()
	defer i.lock.Unlock()

	if label := GetLabel(); len(label) > 0 {
		actor, ok := i.actors[label]
		if !ok {
			panic(fmt.Errorf("expected to find an actor for goroutine label: %s", label))
		}
		return actor
	}

	nextActorID := len(i.actors) + 1
	label := label(nextActorID)
	SetLabel(label)
	i.actors[label] = &actor{id: nextActorID, run: i}
	return i.actors[label]
}

func (i *iteration) Done() {
	if init, ok := i.selector.(interface{ afterRun() }); ok {
		init.afterRun()
	}
}

func (i *iteration) dispatch(w *waiter) {
	i.lock.Lock()
	defer i.lock.Unlock()
	if w != nil {
		i.waiters = append(i.waiters, w)
	} else {
		// an actor is exiting a goroutine
		i.active.Add(-1)
	}

	// we wait for all active actors/goroutines to enter into waiting
	// state, and then we make a decision which actor is selected to
	// resume execution
	if int64(len(i.waiters)) != i.active.Load() {
		// not all active goroutines have entered waiting state yet
		return
	}

	if len(i.waiters) == 0 {
		return
	}
	selected := i.selector.pick(i.waiters)
	if selected < 0 {
		return
	}

	waiter := i.waiters[selected]
	i.waiters = append(i.waiters[0:selected], i.waiters[selected+1:len(i.waiters)]...)
	close(waiter.ch)
	i.sequence = fmt.Sprintf("%s -> %d/%s", i.sequence, waiter.actorID, waiter.op)
}
