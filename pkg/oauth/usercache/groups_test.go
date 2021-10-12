package usercache

import (
	"testing"

	userv1 "github.com/openshift/api/user/v1"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
)

func TestGroupCache_GroupsFor(t *testing.T) {
	tests := []struct {
		name       string
		username   string
		wantGroups sets.String
	}{
		{
			name:     "user with no groups",
			username: "user0",
		},
		{
			name:       "user with some groups",
			username:   "user1",
			wantGroups: sets.NewString("group0", "group2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := &GroupCache{
				indexer:      testGroupsIndexer(t),
				groupsSynced: func() bool { return true },
			}
			got, err := c.GroupsFor(tt.username)
			require.NoError(t, err)

			gotGroupNames := sets.NewString()
			for _, g := range got {
				gotGroupNames.Insert(g.Name)
			}
			if gotGroupNames.Difference(tt.wantGroups).Len() > 0 {
				t.Errorf("wanted groups: %v; but got %v", tt.wantGroups.List(), gotGroupNames.List())
			}
		})
	}
}

func testGroupsIndexer(t *testing.T) cache.Indexer {
	testGroups := []*userv1.Group{
		makeGroup("group0", "user1", "user2", "user3"),
		makeGroup("group1", "user2", "user3"),
		makeGroup("group2", "user1", "user3"),
		makeGroup("group12", "user3"),
		makeGroup("group123"),
	}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		ByUserIndexName: ByUserIndexKeys,
	})
	for _, g := range testGroups {
		require.NoError(t, indexer.Add(g))
	}

	return indexer
}

func makeGroup(groupName string, members ...string) *userv1.Group {
	return &userv1.Group{
		ObjectMeta: v1.ObjectMeta{
			Name: groupName,
		},
		Users: members,
	}
}
