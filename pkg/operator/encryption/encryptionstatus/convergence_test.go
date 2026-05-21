package encryptionstatus

import "testing"

func TestConvergedKEKForKeyID(t *testing.T) {
	reports := []KMSPluginHealthReport{
		{KeyID: "1", NodeName: "master-0", KEKID: "kek-a", Status: "healthy"},
		{KeyID: "1", NodeName: "master-1", KEKID: "kek-a", Status: "healthy"},
		{KeyID: "2", NodeName: "master-0", KEKID: "kek-b", Status: "healthy"},
		{KeyID: "2", NodeName: "master-1", KEKID: "kek-c", Status: "healthy"},
	}

	kekID, ok := ConvergedKEKForKeyID(reports, "1")
	if !ok || kekID != "kek-a" {
		t.Fatalf("expected converged kek-a for key 1, got %q ok=%v", kekID, ok)
	}

	_, ok = ConvergedKEKForKeyID(reports, "2")
	if ok {
		t.Fatal("expected key 2 to be divergent")
	}
}

func TestKEKByKeyIDIgnoresUnhealthy(t *testing.T) {
	reports := []KMSPluginHealthReport{
		{KeyID: "1", NodeName: "master-0", KEKID: "kek-a", Status: "healthy"},
		{KeyID: "1", NodeName: "master-1", KEKID: "kek-b", Status: "healthy"},
		{KeyID: "1", NodeName: "master-2", KEKID: "kek-a", Status: "unhealthy"},
	}
	_, ok := ConvergedKEKForKeyID(reports, "1")
	if ok {
		t.Fatal("expected unhealthy node to be ignored so healthy nodes still diverge")
	}
}
