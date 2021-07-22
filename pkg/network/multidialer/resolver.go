package multidialer

import (
	"context"
	"net"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// resolver updates a local cache with current apiserver address
// and tracks which was the last apiserver connected successfully
type resolver struct {
	mu sync.Mutex
	// apiserver address: true if is a local address
	cache map[string]bool
	// last apiserver connected successfully
	last string
	// local indicates that apiserver is reachable through localhost
}

// NewResolver returns a hosts pool to control the dialer destination
func NewResolver(alternateHosts []string) *resolver {
	hosts := map[string]bool{}
	if len(alternateHosts) > 0 {
		for _, h := range alternateHosts {
			hosts[h] = false
		}
	}
	return &resolver{
		cache: hosts,
	}
}

// setLast records the last host successfully connected
func (r *resolver) setLast(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.last = host
}

// updateCache updates the cache with a new list of apiserver endpoints
func (r *resolver) updateCache(hosts []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// check if one of the addresses is present on the host
	localAddresses := getLocalAddrs()
	r.cache = map[string]bool{}
	for _, h := range hosts {
		r.cache[h] = localAddresses[h]
	}
}

// listReady returns an ordered list only with the hosts that are ready
// 1. try first the endpoints that are local
// 2. try the last one connected
// 3. try the rest of endpoints
func (r *resolver) listReady() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	hosts := []string{}
	localhost := false
	for k, v := range r.cache {
		// detect if there is any local address
		if v {
			localhost = true
			continue
		}
		// prepend if is the last good one
		// so we try to connect against it first
		if k == r.last {
			hosts = append([]string{k}, hosts...)
		} else {
			hosts = append(hosts, k)
		}
	}
	// if there is a local address we try to connect
	// first overriding the endpoint ip address by "localhost"
	if localhost {
		hosts = append([]string{"localhost"}, hosts...)
	}
	return hosts
}

// start starts a loop to get the apiserver endpoints from the apiserver
// so the dialer can connect to the registered apiservers in the cluster.
// This is the tricky part, since the resolver uses the same dialer it feeds
// so it will benefit from the resilience it provides.
func (r *resolver) start(ctx context.Context, clientset kubernetes.Interface) {
	// run a goroutine updating the apiserver hosts in the dialer
	// this handle cluster resizing and renumbering
	go func() {
		// add the list of alternate hosts to the dialer obtained from the apiserver endpoints
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// apiservers are registered as endpoints of the kubernetes.default service
			endpoint, err := clientset.CoreV1().Endpoints("default").Get(context.TODO(), "kubernetes", metav1.GetOptions{})
			if err != nil || len(endpoint.Subsets) == 0 {
				continue
			}
			newHosts := []string{}
			// get current hosts
			for _, ss := range endpoint.Subsets {
				for _, e := range ss.Addresses {
					newHosts = append(newHosts, e.IP)
				}
			}
			// update the cache with the new hosts
			r.updateCache(newHosts)
			time.Sleep(60 * time.Second)
		}
	}()
}

// getLocalAddrs returns a list of all network addresses on the local system
func getLocalAddrs() map[string]bool {
	localAddrs := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return localAddrs
	}
	for _, addr := range addrs {
		localAddrs[addr.String()] = true
	}
	return localAddrs
}
