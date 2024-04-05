package linearizer

import (
	"fmt"
	"sync"
	"testing"
)

func TestGoRoutineLabel(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(4)
	for i := 0; i < 2; i++ {
		go func(label string) {
			defer wg.Done()
			SetLabel(label)
			go func() {
				defer wg.Done()
				labelGot := GetLabel()
				if label != labelGot {
					t.Errorf("expected label to match, want: %s, got: %s", label, labelGot)
				}
			}()
		}(fmt.Sprintf("actor-%d", i+1))
	}

	wg.Wait()
}

/*
   A controller has this sequence: Get, Create, and Update
   Two instances of the controller: A, and B
   The two instances run on their own goroutine, and we try to exercise
   all possible combinations:
     -- A/Start -> A/Get   -> A/Create -> A/Update -> B/Start  -> B/Get    -> B/Create -> B/Update
     -- A/Start -> B/Start -> A/Get    -> A/Create -> A/Update -> B/Get    -> B/Create -> B/Update
     -- A/Start -> A/Get   -> B/Start  -> A/Create -> A/Update -> B/Get    -> B/Create -> B/Update
     -- A/Start -> A/Get   -> A/Create -> B/Start  -> A/Update -> B/Get    -> B/Create -> B/Update
     -- A/Start -> B/Start -> B/Get    -> A/Get    -> A/Create -> A/Update -> B/Create -> B/Update
     -- A/Start -> B/Start -> A/Get    -> B/Get    -> A/Create -> A/Update -> B/Create -> B/Update
     -- A/Start -> A/Get   -> B/Start  -> B/Get    -> A/Create -> A/Update -> B/Create -> B/Update
     -- A/Start -> B/Start -> A/Get    -> A/Create -> B/Get    -> A/Update -> B/Create -> B/Update
     -- (more)
*/

func TestLinearizer(t *testing.T) {
	actors := 2
	exhaustive := &Exhaustive{}
	d := NewIterationCoordinator(t, actors, exhaustive)

	for d.More() {
		t.Run("", func(t *testing.T) {
			// step 2: scoped to an run/iteration
			run := d.NewIteration(t)
			defer run.Done()

			var wg sync.WaitGroup
			wg.Add(actors)
			for i := 0; i < actors; i++ {
				func() {
					go func() {
						defer wg.Done()

						// we need to associate the controller instance to
						// exactly one goroutine
						actor := run.GetMyActor()
						defer actor.Exit()    // exiting goroutine
						<-actor.Wait("Start") // wait for the dispatcher to unblock

						c := controller{actor: actor}
						c.sync()
					}()
				}()
			}

			wg.Wait()
			t.Logf("sequence: %s", run.Sequence())
		})
	}
	exhaustive.Report()
}

type controller struct {
	actor Actor
}

func (c controller) G() { <-c.actor.Wait("Get") }
func (c controller) C() { <-c.actor.Wait("Create") }
func (c controller) U() { <-c.actor.Wait("Update") }

func (c controller) sync() {
	c.G()
	c.C()
	c.U()
}
