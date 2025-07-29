package status

import (
	"reflect"
	"testing"
	"time"
)

func TestVersionGetterBasic(t *testing.T) {
	versionGetter := NewVersionGetter()
	versions := versionGetter.GetVersions()
	if versions == nil {
		t.Fatal(versions)
	}

	ch := versionGetter.VersionChangedChannel()
	if ch == nil {
		t.Fatal(ch)
	}

	versionGetter.SetVersion("foo", "bar")

	select {
	case <-ch:
		actual := versionGetter.GetVersions()
		expected := map[string]string{"foo": "bar"}
		if !reflect.DeepEqual(expected, actual) {
			t.Fatal(actual)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("missing")
	}

}

func TestVersionGetterUnset(t *testing.T) {
	versionGetter := NewVersionGetter()

	versionGetter.UnsetVersion("nonexistent")
	expected := map[string]string{}
	versions := versionGetter.GetVersions()
	if !reflect.DeepEqual(expected, versions) {
		t.Fatalf("Expected %v, got %v", expected, versions)
	}

	versionGetter.SetVersion("foo", "1.0.0")
	versionGetter.SetVersion("bar", "2.0.0")

	versions = versionGetter.GetVersions()
	expected = map[string]string{"foo": "1.0.0", "bar": "2.0.0"}
	if !reflect.DeepEqual(expected, versions) {
		t.Fatalf("wanted: %v; got: %v", expected, versions)
	}

	ch := versionGetter.VersionChangedChannel()
	versionGetter.UnsetVersion("foo")

	select {
	case <-ch:
		// we got notified
	case <-time.After(5 * time.Second):
		t.Fatal("expected change notification after UnsetVersion but didn't get any")
	}

	versions = versionGetter.GetVersions()
	expected = map[string]string{"bar": "2.0.0"}
	if !reflect.DeepEqual(expected, versions) {
		t.Fatalf("Expected %v, got %v", expected, versions)
	}

	versionGetter.UnsetVersion("nonexistent")
	versions = versionGetter.GetVersions()
	if !reflect.DeepEqual(expected, versions) {
		t.Fatalf("Expected %v, got %v", expected, versions)
	}
}
