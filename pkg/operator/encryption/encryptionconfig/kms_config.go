package encryptionconfig

import (
	"encoding/hex"
	"fmt"
	"hash"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/davecgh/go-spew/spew"
)

const (
	KMSPluginEndpoint = "unix:///var/kms-plugin/socket.sock"
	KMSPluginTimeout  = 5 * time.Second
)

var hasher = fnv.New64a()

// shortHash returns the 32-bit FNV-1a hash
func shortHash(s string) string {
	hash := fnv.New32a()
	hash.Write([]byte(s))
	intHash := hash.Sum32()
	result := fmt.Sprintf("%08x", intHash)
	return result
}

// resourceHash hashes GR names into a short hash.
// This function can input multiple resource names at based on upstream apiserverconfigv1.ResourceConfiguration
// but in our controllers we only support one GR per provider.
func resourceHash(grs ...schema.GroupResource) string {
	res := make([]string, len(grs))
	for i, gr := range grs {
		res[i] = gr.String()
	}
	sort.Strings(res)
	return shortHash(strings.Join(res, "+"))
}

// generateKMSKeyName generates key name for current kms provider
func generateKMSKeyName(prefix string, gr schema.GroupResource) string {
	return fmt.Sprintf("%s-%s", prefix, resourceHash(gr))
}

// HashObject will hash any object using a provided hasher
func HashObject(hasher hash.Hash, objectToWrite interface{}) string {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
	return hex.EncodeToString(hasher.Sum(nil)[0:])
}

// HashKMSConfig returns a short FNV 64-bit hash for a KMSConfig struct
func HashKMSConfig(config configv1.KMSConfig) string {
	return HashObject(hasher, config)
}
