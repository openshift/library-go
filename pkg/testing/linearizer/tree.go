package linearizer

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func NewExhaustiveSelector() *Exhaustive {
	return &Exhaustive{}
}

type node struct {
	parent          *node
	nodeID, actorID int
	label           string
	visited         int
	children        []*node
	failed          bool
}

func newNode(nodeID, actorID int) *node {
	return &node{nodeID: nodeID, actorID: actorID, visited: 1}
}

func newNodeWithWaiter(parent *node, nodeID int, w *waiter) *node {
	return &node{
		parent:  parent,
		nodeID:  nodeID,
		actorID: w.actorID,
		label:   w.op,
		visited: 1,
	}
}

// maintains an in-memory tree of all the sequences so far to find the next
// unexplored linearized sequence
// TODO: need to do more work on making sure it can gnerate all possible
// sequences
type Exhaustive struct {
	t            *testing.T
	sequence     int
	root         *node
	current      *node
	runs, repeat int
	exhausted    bool
}

func (e *Exhaustive) nextID() int {
	e.sequence++
	return e.sequence
}

func (e *Exhaustive) pick(w []*waiter) int {
	if len(w) == 0 {
		return -1
	}
	sortByIActorID(w)

	switch {
	case e.root == nil:
		e.root = newNodeWithWaiter(nil, e.nextID(), w[0])
		e.current = e.root
		return 0
	case e.current == nil:
		// a new run, we choose the same actor to prune duplicate runs
		// we always let the actor that started first, always start first
		indx := ByActorID(w).find(e.root.actorID)
		if indx < 0 {
			e.t.Errorf("expected to find the actor: %d", e.root.actorID)
			return -1
		}
		e.current = e.root
		e.current.visited++
		return indx
	default:
		if len(e.current.children) == 0 {
			child := newNodeWithWaiter(e.current, e.nextID(), w[0])
			e.current.children = append(e.current.children, child)
			e.current = child
			return 0
		}
		current, indx := e.next(e.current, w)
		e.current = current
		return indx
	}
}

func (e *Exhaustive) afterRun() {
	e.runs++
	curr := e.current
	e.current = nil
	if curr.visited > 1 {
		e.repeat++
		e.t.Logf("a possible repeat run: %d", curr.visited)
	}
	if e.t.Failed() {
		for child := curr; child != nil; {
			child.failed = true
			child = child.parent
		}
	}

	n := rightmost(e.root)
	if n.visited > 1 {
		e.exhausted = true
	}
}

func (e *Exhaustive) more() bool { return !e.exhausted }

func (e *Exhaustive) beforeRun(t *testing.T) { e.t = t }

func (e *Exhaustive) Report() {
	e.t.Logf("total iterations: %d, repeat: %d", e.runs, e.repeat)
	e.t.Logf("graph\n\n%s", e.graphviz(e.root))
}

// selects the next waiter based on the current state
// TODO: it's a prototype, needs more polishing/optimization
func (e *Exhaustive) next(parent *node, w []*waiter) (*node, int) {
	indx := -1
	for i, waiter := range w {
		var found bool
		for _, child := range parent.children {
			if waiter.actorID == child.actorID {
				found = true
				break
			}
		}
		if !found {
			indx = i
		}
	}
	if indx >= 0 {
		node := newNodeWithWaiter(parent, e.nextID(), w[indx])
		parent.children = append(parent.children, node)
		return node, indx
	}

	// if we are here, every waiter has a matching node
	// we have to select the node with least visits
	minVisited := math.MaxInt32
	var minVisitedNode *node
	for i := range parent.children {
		child := parent.children[i]
		if child.visited < minVisited {
			minVisited = child.visited
			minVisitedNode = child
		}
	}
	indx = ByActorID(w).find(minVisitedNode.actorID)
	minVisitedNode.visited++
	return minVisitedNode, indx
}

func rightmost(parent *node) *node {
	n := parent
	for children := n.children; len(children) > 0; {
		n = children[len(children)-1]
		children = n.children
	}
	return n
}

func (e *Exhaustive) graphviz(parent *node) string {
	var sb strings.Builder
	sb.WriteString("digraph G {\n\n")

	nodes := make([]*node, 0)
	nodes = append(nodes, parent)
	for len(nodes) > 0 {
		from := nodes[0]
		nodes = append(nodes[1:], from.children...)

		label := fmt.Sprintf("\t%d [label=\"%d(%s)\"]\n", from.nodeID, from.actorID, from.label)
		sb.WriteString(label)
		for _, child := range from.children {
			color := ""
			if from.failed && child.failed {
				color = " [color=red]"
			}

			sb.WriteString(fmt.Sprintf("\t%d -> %d%s;\n", from.nodeID, child.nodeID, color))
		}
	}

	sb.WriteString("\n}\n")
	return sb.String()
}
