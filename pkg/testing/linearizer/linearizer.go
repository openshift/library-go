package linearizer

import (
	"testing"
)

type IterationCoordinator interface {
	NewIteration(*testing.T) Iteration
	More() bool
}

type Iteration interface {
	GetMyActor() Actor
	Done()
	Sequence() string
}

func NewIterationCoordinator(t *testing.T, actors int, selector selector) *coordinator {
	return &coordinator{t: t, count: actors, selector: selector}
}

type coordinator struct {
	t        *testing.T
	count    int
	selector selector
}

func (c *coordinator) More() bool { return c.selector.more() }

func (c *coordinator) NewIteration(t *testing.T) Iteration {
	if selector, ok := c.selector.(interface{ beforeRun(*testing.T) }); ok {
		selector.beforeRun(t)
	}

	i := &iteration{
		actors:   map[string]*actor{},
		selector: c.selector,
	}
	i.active.Store(int64(c.count))
	return i
}
