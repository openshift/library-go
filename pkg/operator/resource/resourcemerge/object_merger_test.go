package resourcemerge

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestMergeOwnerRefs(t *testing.T) {
	tests := []struct {
		name     string
		existing []metav1.OwnerReference
		required []metav1.OwnerReference
		expected []metav1.OwnerReference
		modified bool
	}{
		{
			name:     "do not update when all is nil",
			existing: nil,
			required: nil,
			expected: []metav1.OwnerReference{},
			modified: false,
		},
		{
			name:     "do not update when required is nil",
			existing: []metav1.OwnerReference{newOwnerRef("Kind", "test", "group/v1", "uid1")},
			required: nil,
			expected: []metav1.OwnerReference{newOwnerRef("Kind", "test", "group/v1", "uid1")},
			modified: false,
		},
		{
			name:     "update owner when existing is nil",
			existing: nil,
			required: []metav1.OwnerReference{newOwnerRef("Kind", "test", "group/v1", "uid1")},
			expected: []metav1.OwnerReference{newOwnerRef("Kind", "test", "group/v1", "uid1")},
			modified: true,
		},
		{
			name:     "add aditional owner to the existing owners",
			existing: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1"), newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			required: []metav1.OwnerReference{newOwnerRef("Kind1", "test1", "group/v1", "uid3"), newOwnerRef("Kind1", "test1", "group1/v1", "uid4")},
			expected: []metav1.OwnerReference{
				newOwnerRef("Kind", "test1", "group/v1", "uid1"),
				newOwnerRef("Kind", "test2", "group/v1", "uid2"),
				newOwnerRef("Kind1", "test1", "group/v1", "uid3"),
				newOwnerRef("Kind1", "test1", "group1/v1", "uid4"),
			},
			modified: true,
		},
		{
			name:     "remove an existing owners",
			existing: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1"), newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			required: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1-")},
			expected: []metav1.OwnerReference{newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			modified: true,
		},
		{
			name:     "remove a non-existing owner",
			existing: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1"), newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			required: []metav1.OwnerReference{newOwnerRef("Kind", "test3", "group/v1", "uid1-")},
			expected: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1"), newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			modified: false,
		},
		{
			name:     "do not update with same owners",
			existing: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1"), newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			required: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1"), newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			expected: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1"), newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			modified: false,
		},
		{
			name:     "update the existing owners",
			existing: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid1"), newOwnerRef("Kind", "test2", "group/v1", "uid2")},
			required: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid3"), newOwnerRef("Kind", "test2", "group/v1", "uid4")},
			expected: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "group/v1", "uid3"), newOwnerRef("Kind", "test2", "group/v1", "uid4")},
			modified: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modified := false
			MergeOwnerRefs(&modified, &test.existing, test.required)

			if !reflect.DeepEqual(test.existing, test.expected) {
				t.Errorf("expected got ownerrefs %v, but got %v", test.expected, test.existing)
			}

			if test.modified != modified {
				t.Errorf("expected ownerrefs updates with %t, but got %t", test.modified, modified)
			}
		})
	}
}

func TestCleanOwnerRefs(t *testing.T) {
	tests := []struct {
		name     string
		required []metav1.OwnerReference
		expected []metav1.OwnerReference
	}{
		{
			name:     "ownerrefs is nil",
			required: nil,
			expected: nil,
		},
		{
			name:     "remove 1 ownerrefs",
			required: []metav1.OwnerReference{newOwnerRef("Kind", "test", "v1", "test-")},
			expected: []metav1.OwnerReference{},
		},
		{
			name: "remove multiple ownerrefs",
			required: []metav1.OwnerReference{
				newOwnerRef("Kind", "test", "v1", "test-"),
				newOwnerRef("Kind", "test1", "v1", "test1"),
				newOwnerRef("Kind", "test2", "v1", "test2-"),
			},
			expected: []metav1.OwnerReference{newOwnerRef("Kind", "test1", "v1", "test1")},
		},
		{
			name: "no action if there is no removal key",
			required: []metav1.OwnerReference{
				newOwnerRef("Kind", "test1", "v1", "test1"),
				newOwnerRef("Kind", "test2", "v1", "test2"),
			},
			expected: []metav1.OwnerReference{
				newOwnerRef("Kind", "test1", "v1", "test1"),
				newOwnerRef("Kind", "test2", "v1", "test2"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			required := cleanRemovalOwnerRefs(test.required)

			if !reflect.DeepEqual(test.expected, required) {
				t.Errorf("expected got ownerrefs %v, but got %v", test.expected, test.required)
			}
		})
	}
}

func newOwnerRef(kind, name, apiVersion, uid string) metav1.OwnerReference {
	return metav1.OwnerReference{
		Name:       name,
		Kind:       kind,
		APIVersion: apiVersion,
		UID:        types.UID(uid),
	}
}
