package usercache

import (
	"fmt"
	"k8s.io/client-go/tools/cache"

	userapi "github.com/openshift/api/user/v1"
	userinformer "github.com/openshift/client-go/user/informers/externalversions/user/v1"
)

// GroupCache is a skin on an indexer to provide the reverse index from user to groups.
// Once we work out a cleaner way to extend a lister, this should live there.
type GroupCache struct {
	indexer      cache.Indexer
	groupsSynced cache.InformerSynced
}

const ByUserIndexName = "ByUser"

// ByUserIndexKeys is cache.IndexFunc for Groups that will index groups by User, so that a direct cache lookup
// using a User.Name will return all Groups that User is a member of
func ByUserIndexKeys(obj interface{}) ([]string, error) {
	group, ok := obj.(*userapi.Group)
	if !ok {
		return nil, fmt.Errorf("unexpected type: %v", obj)
	}

	return group.Users, nil
}

func NewGroupCache(groupInformer userinformer.GroupInformer) *GroupCache {
	return &GroupCache{
		indexer:      groupInformer.Informer().GetIndexer(),
		groupsSynced: groupInformer.Informer().HasSynced,
	}
}

func (c *GroupCache) GroupsFor(username string) ([]*userapi.Group, error) {
	objs, err := c.indexer.ByIndex(ByUserIndexName, username)
	if err != nil {
		return nil, err
	}

	groups := []*userapi.Group{}
	for i := range objs {
		switch t := objs[i].(type) {
		case *userapi.Group:
			groups = append(groups, t)
		case nil:
			// if there is a race and something remove the groups from this user, skip it
			// TODO: we should investigate this more and probably use non-racy informer here?
			continue
		default:
			// if the type is not nil nor group, panic
			panic(fmt.Sprintf("possible race: unexpected object of type %T found in group cache indexer", objs[i]))
		}
	}

	return groups, nil
}

func (c *GroupCache) HasSynced() bool {
	return c.groupsSynced()
}
