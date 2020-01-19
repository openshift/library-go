package verifyconfigmap

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
)

// ReleaseLabelConfigMap is a label applied to a configmap inside the
// openshift-config-managed namespace that indicates it contains signatures
// for release image digests. Any binaryData key that starts with the digest
// is added to the list of signatures checked.
const ReleaseLabelConfigMap = "release.openshift.io/verification-signatures"

// Store abstracts retrieving signatures from config maps on a cluster.
type Store struct {
	client corev1client.ConfigMapsGetter
	ns     string

	limiter *rate.Limiter
	lock    sync.Mutex
	last    []corev1.ConfigMap
}

// NewStore returns a store that can retrieve or persist signatures on a
// cluster. If limiter is not specified it defaults to one call every 30 seconds.
func NewStore(client corev1client.ConfigMapsGetter, limiter *rate.Limiter) *Store {
	if limiter == nil {
		limiter = rate.NewLimiter(rate.Every(30*time.Second), 1)
	}
	return &Store{
		client: client,
		ns:     "openshift-config-managed",
	}
}

// String displays information about this source for human review.
func (s *Store) String() string {
	return fmt.Sprintf("config maps in %s with label %q", s.ns, ReleaseLabelConfigMap)
}

// rememberMostRecentConfigMaps stores a set of config maps containing
// signatures.
func (s *Store) rememberMostRecentConfigMaps(last []corev1.ConfigMap) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.last = last
}

// mostRecentConfigMaps returns the last cached version of config maps
// containing signatures.
func (s *Store) mostRecentConfigMaps() []corev1.ConfigMap {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.last
}

// DigestSignatures returns a list of signatures that match the request
// digest out of config maps labelled with ReleaseLabelConfigMap in the
// openshift-config-managed namespace.
func (s *Store) DigestSignatures(ctx context.Context, digest string) ([][]byte, error) {
	// avoid repeatedly reloading config maps
	items := s.mostRecentConfigMaps()
	r := s.limiter.Reserve()
	if items == nil || r.OK() {
		configMaps, err := s.client.ConfigMaps(s.ns).List(metav1.ListOptions{
			LabelSelector: ReleaseLabelConfigMap,
		})
		if err != nil {
			s.rememberMostRecentConfigMaps([]corev1.ConfigMap{})
			return nil, err
		}
		items = configMaps.Items
		s.rememberMostRecentConfigMaps(configMaps.Items)
	}

	var signatures [][]byte
	for _, cm := range items {
		for k, v := range cm.BinaryData {
			if strings.HasPrefix(k, digest) {
				signatures = append(signatures, v)
			}
		}
	}
	return signatures, nil
}

// Store attempts to persist the provided signatures into a form DigestSignatures will
// retrieve.
func (s *Store) Store(ctx context.Context, signaturesByDigest map[string][][]byte) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.ns,
			Name:      "signatures-managed",
			Labels: map[string]string{
				ReleaseLabelConfigMap: "",
			},
		},
		BinaryData: make(map[string][]byte),
	}
	for digest, signatures := range signaturesByDigest {
		for i := 0; i < len(signatures); i++ {
			cm.BinaryData[fmt.Sprintf("%s-%d", digest, i)] = signatures[i]
		}
	}
	return retry.OnError(
		retry.DefaultRetry,
		func(err error) bool { return errors.IsConflict(err) || errors.IsAlreadyExists(err) },
		func() error {
			existing, err := s.client.ConfigMaps(s.ns).Get(cm.Name, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				_, err := s.client.ConfigMaps(s.ns).Create(cm)
				return err
			}
			if err != nil {
				return err
			}
			existing.Labels = cm.Labels
			existing.BinaryData = cm.BinaryData
			existing.Data = cm.Data
			_, err = s.client.ConfigMaps(s.ns).Update(existing)
			return err
		},
	)
}
