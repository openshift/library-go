package capability

import (
	"errors"
	"os"
	"testing"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/library-go/pkg/manifest"
)

func TestGetImplicitlyEnabledCapabilitiesInternal(t *testing.T) {
	tests := []struct {
		name           string
		enabledManCaps []configv1.ClusterVersionCapability
		updatedManCaps []configv1.ClusterVersionCapability
		capabilities   ClusterCapabilities
		wantImplicit   []string
	}{
		{name: "implicitly enable capability",
			enabledManCaps: []configv1.ClusterVersionCapability{"cap1", "cap3"},
			updatedManCaps: []configv1.ClusterVersionCapability{"cap2"},
			capabilities: ClusterCapabilities{
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
			},
			wantImplicit: []string{"cap2"},
		},
		{name: "no prior caps, implicitly enabled capability",
			updatedManCaps: []configv1.ClusterVersionCapability{"cap2"},
			wantImplicit:   []string{"cap2"},
		},
		{name: "multiple implicitly enable capability",
			enabledManCaps: []configv1.ClusterVersionCapability{"cap1", "cap2", "cap3"},
			updatedManCaps: []configv1.ClusterVersionCapability{"cap4", "cap5", "cap6"},
			wantImplicit:   []string{"cap4", "cap5", "cap6"},
		},
		{name: "no implicitly enable capability",
			enabledManCaps: []configv1.ClusterVersionCapability{"cap1", "cap3"},
			updatedManCaps: []configv1.ClusterVersionCapability{"cap1"},
			capabilities: ClusterCapabilities{
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
			},
		},
		{name: "prior cap, no updated caps, no implicitly enabled capability",
			enabledManCaps: []configv1.ClusterVersionCapability{"cap1"},
		},
		{name: "no implicitly enable capability, already enabled",
			enabledManCaps: []configv1.ClusterVersionCapability{"cap1", "cap2"},
			updatedManCaps: []configv1.ClusterVersionCapability{"cap2"},
			capabilities: ClusterCapabilities{
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap1": {}, "cap2": {}},
			},
		},
		{name: "no implicitly enable capability, new cap but already enabled",
			enabledManCaps: []configv1.ClusterVersionCapability{"cap1"},
			updatedManCaps: []configv1.ClusterVersionCapability{"cap2"},
			capabilities: ClusterCapabilities{
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap2": {}},
			},
		},
		{name: "no implicitly enable capability, already implcitly enabled",
			enabledManCaps: []configv1.ClusterVersionCapability{"cap1"},
			updatedManCaps: []configv1.ClusterVersionCapability{"cap2"},
			capabilities: ClusterCapabilities{
				EnabledCapabilities:           map[configv1.ClusterVersionCapability]struct{}{"cap2": {}},
				ImplicitlyEnabledCapabilities: []configv1.ClusterVersionCapability{"cap2"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			caps := getImplicitlyEnabledCapabilities(test.enabledManCaps, test.updatedManCaps, test.capabilities)
			if len(caps) != len(test.wantImplicit) {
				t.Errorf("Incorrect number of implicitly enabled keys, wanted: %d. Implicitly enabled capabilities returned: %v", len(test.wantImplicit), caps)
			}
			for _, wanted := range test.wantImplicit {
				found := false
				for _, have := range caps {
					if wanted == string(have) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Missing implicitly enabled capability %q. Implicitly enabled capabilities returned : %v", wanted, caps)
				}
			}
		})
	}
}

func TestGetCapabilitiesStatus(t *testing.T) {
	tests := []struct {
		name       string
		caps       ClusterCapabilities
		wantStatus configv1.ClusterVersionCapabilitiesStatus
	}{
		{name: "empty capabilities",
			caps: ClusterCapabilities{
				KnownCapabilities:   map[configv1.ClusterVersionCapability]struct{}{},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{},
			},
			wantStatus: configv1.ClusterVersionCapabilitiesStatus{
				EnabledCapabilities: []configv1.ClusterVersionCapability{},
				KnownCapabilities:   []configv1.ClusterVersionCapability{},
			},
		},
		{name: "capabilities",
			caps: ClusterCapabilities{
				KnownCapabilities:   map[configv1.ClusterVersionCapability]struct{}{configv1.ClusterVersionCapabilityOpenShiftSamples: {}},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{configv1.ClusterVersionCapabilityOpenShiftSamples: {}},
			},
			wantStatus: configv1.ClusterVersionCapabilitiesStatus{
				EnabledCapabilities: []configv1.ClusterVersionCapability{configv1.ClusterVersionCapabilityOpenShiftSamples},
				KnownCapabilities:   []configv1.ClusterVersionCapability{configv1.ClusterVersionCapabilityOpenShiftSamples},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := GetCapabilitiesStatus(test.caps)
			if len(config.KnownCapabilities) != len(test.wantStatus.KnownCapabilities) {
				t.Errorf("Incorrect number of KnownCapabilities keys, wanted: %q. KnownCapabilities returned: %v",
					test.wantStatus.KnownCapabilities, config.KnownCapabilities)
			}
			for _, v := range test.wantStatus.KnownCapabilities {
				vFound := false
				for _, cv := range config.KnownCapabilities {
					if v == cv {
						vFound = true
						break
					}
					if !vFound {
						t.Errorf("Missing KnownCapabilities key %q. KnownCapabilities returned : %v", v, config.KnownCapabilities)
					}
				}
			}
			if len(config.EnabledCapabilities) != len(test.wantStatus.EnabledCapabilities) {
				t.Errorf("Incorrect number of EnabledCapabilities keys, wanted: %q. EnabledCapabilities returned: %v",
					test.wantStatus.EnabledCapabilities, config.EnabledCapabilities)
			}
			for _, v := range test.wantStatus.EnabledCapabilities {
				vFound := false
				for _, cv := range config.EnabledCapabilities {
					if v == cv {
						vFound = true
						break
					}
					if !vFound {
						t.Errorf("Missing EnabledCapabilities key %q. EnabledCapabilities returned : %v", v, config.EnabledCapabilities)
					}
				}
			}
		})
	}
}

func TestGetImplicitlyEnabledCapabilities(t *testing.T) {
	const testsPath = "testdata/GetImplicitlyEnabledCapabilities/"

	tests := []struct {
		name               string
		pathExt            string
		updateAnnotations  map[string]interface{}
		currentAnnotations map[string]interface{}
		capabilities       ClusterCapabilities
		wantImplicit       []configv1.ClusterVersionCapability
		wantImplicitLen    int
	}{
		{
			name:    "basic",
			pathExt: "test1",
			capabilities: ClusterCapabilities{
				KnownCapabilities:   map[configv1.ClusterVersionCapability]struct{}{"cap1": {}, "cap2": {}},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
			},
			wantImplicit: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap2"),
			},
			wantImplicitLen: 1,
		},
		{
			name:    "basic with unknown cap",
			pathExt: "test1",
			capabilities: ClusterCapabilities{
				KnownCapabilities:   map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
			},
			wantImplicit: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap2"),
			},
			wantImplicitLen: 1,
		},
		{
			name:    "different manifest",
			pathExt: "test2",
		},
		{
			name:    "current manifest not enabled",
			pathExt: "test3",
			capabilities: ClusterCapabilities{
				KnownCapabilities:   map[configv1.ClusterVersionCapability]struct{}{"cap2": {}},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap2": {}},
			},
		},
		{
			name:    "new cap already enabled",
			pathExt: "test4",
			capabilities: ClusterCapabilities{
				KnownCapabilities:   map[configv1.ClusterVersionCapability]struct{}{"cap1": {}, "cap2": {}},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap1": {}, "cap2": {}},
			},
		},
		{
			name:    "already implicitly enabled",
			pathExt: "test5",
			capabilities: ClusterCapabilities{
				KnownCapabilities:             map[configv1.ClusterVersionCapability]struct{}{"cap1": {}, "cap2": {}},
				EnabledCapabilities:           map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
				ImplicitlyEnabledCapabilities: []configv1.ClusterVersionCapability{"cap2"},
			},
			wantImplicit: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap2"),
			},
			wantImplicitLen: 1,
		},
		{
			name:    "only add cap once",
			pathExt: "test6",
			capabilities: ClusterCapabilities{
				KnownCapabilities:   map[configv1.ClusterVersionCapability]struct{}{"cap1": {}, "cap2": {}},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
			},
			wantImplicit: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap2"),
			},
			wantImplicitLen: 1,
		},
		{
			/*
				Grep manifest file data to understand results:
				$ grep cap ../cvo/testdata/payloadcapabilitytest/test7/current/fil*
				grep cap ../cvo/testdata/payloadcapabilitytest/test7/update/fil*
			*/

			name:    "complex",
			pathExt: "test7",
			capabilities: ClusterCapabilities{
				KnownCapabilities: map[configv1.ClusterVersionCapability]struct{}{
					"cap1": {}, "cap2": {}, "cap3": {}, "cap4": {}, "cap5": {}, "cap6": {},
					"cap7": {}, "cap8": {}, "cap9": {}, "cap10": {}, "cap11": {}, "cap12": {},
					"cap13": {}, "cap14": {}, "cap15": {}, "cap16": {}, "cap17": {}, "cap18": {},
					"cap19": {}, "cap20": {}, "cap21": {}, "cap22": {}, "cap23": {}, "cap24": {},
					"cap111": {}, "cap112": {}, "cap113": {}, "cap114": {}, "cap115": {}, "cap116": {},
					"cap117": {}, "cap118": {}, "cap119": {}, "cap1111": {}, "cap1113": {}, "cap1115": {},
					"cap1110": {}, "cap1112": {}, "cap1114": {}, "cap1116": {},
				},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{
					"cap1": {}, "cap2": {}, "cap3": {}, "cap4": {}, "cap5": {}, "cap6": {},
					"cap7": {}, "cap8": {}, "cap9": {}, "cap10": {}, "cap11": {}, "cap12": {},
					"cap13": {}, "cap14": {}, "cap15": {}, "cap16": {}, "cap17": {}, "cap18": {},
					"cap19": {}, "cap20": {}, "cap21": {}, "cap22": {}, "cap23": {}, "cap24": {},
				},
				ImplicitlyEnabledCapabilities: []configv1.ClusterVersionCapability{
					configv1.ClusterVersionCapability("cap000"),
					configv1.ClusterVersionCapability("cap111"),
					configv1.ClusterVersionCapability("cap112"),
					configv1.ClusterVersionCapability("cap113"),
					configv1.ClusterVersionCapability("cap114"),
				},
			},
			wantImplicit: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap000"),
				configv1.ClusterVersionCapability("cap111"),
				configv1.ClusterVersionCapability("cap112"),
				configv1.ClusterVersionCapability("cap113"),
				configv1.ClusterVersionCapability("cap114"),
				configv1.ClusterVersionCapability("cap115"),
				configv1.ClusterVersionCapability("cap116"),
				configv1.ClusterVersionCapability("cap117"),
				configv1.ClusterVersionCapability("cap118"),
				configv1.ClusterVersionCapability("cap119"),
				configv1.ClusterVersionCapability("cap1110"),
				configv1.ClusterVersionCapability("cap1111"),
				configv1.ClusterVersionCapability("cap1112"),
				configv1.ClusterVersionCapability("cap1113"),
				configv1.ClusterVersionCapability("cap1114"),
				configv1.ClusterVersionCapability("cap1115"),
				configv1.ClusterVersionCapability("cap1116"),
			},
			wantImplicitLen: 17,
		},
		{
			name:    "no update manifests",
			pathExt: "test8",
			capabilities: ClusterCapabilities{
				KnownCapabilities:             map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
				EnabledCapabilities:           map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
				ImplicitlyEnabledCapabilities: []configv1.ClusterVersionCapability{"cap1"},
			},
			wantImplicit: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap1"),
			},
			wantImplicitLen: 1,
		},
		{
			name:    "no current manifests",
			pathExt: "test9",
			capabilities: ClusterCapabilities{
				KnownCapabilities:             map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
				EnabledCapabilities:           map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
				ImplicitlyEnabledCapabilities: []configv1.ClusterVersionCapability{"cap1"},
			},
			wantImplicit: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap1"),
			},
			wantImplicitLen: 1,
		},
		{
			name:    "duplicate manifests",
			pathExt: "test10",
			capabilities: ClusterCapabilities{
				KnownCapabilities:   map[configv1.ClusterVersionCapability]struct{}{"cap1": {}, "cap2": {}},
				EnabledCapabilities: map[configv1.ClusterVersionCapability]struct{}{"cap1": {}},
			},
			wantImplicit: []configv1.ClusterVersionCapability{
				configv1.ClusterVersionCapability("cap2"),
			},
			wantImplicitLen: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := testsPath + tt.pathExt + "/current"
			currentMans, err := readManifestFiles(path)
			if err != nil {
				t.Fatal(err)
			}
			path = testsPath + tt.pathExt + "/update"
			updateMans, err := readManifestFiles(path)
			if err != nil {
				t.Fatal(err)
			}
			// readManifestFiles does not allow dup manifests so hacking in here.
			if tt.pathExt == "test10" {
				updateMans = append(updateMans, updateMans[0])
			}
			caps := GetImplicitlyEnabledCapabilities(updateMans, currentMans, tt.capabilities)
			if len(caps) != tt.wantImplicitLen {
				t.Errorf("Incorrect number of implicitly enabled keys, wanted: %d. Implicitly enabled capabilities returned: %v", tt.wantImplicitLen, caps)
			}
			for _, wanted := range tt.wantImplicit {
				found := false
				for _, have := range caps {
					if wanted == have {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Missing implicitly enabled capability %q. Implicitly enabled capabilities returned : %v", wanted, caps)
				}
			}
		})
	}
}

func readManifestFiles(path string) ([]manifest.Manifest, error) {
	readFiles, err := os.ReadDir(path)

	// no dir for nil tests
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	files := []string{}
	for _, f := range readFiles {
		if !f.IsDir() {
			files = append(files, path+"/"+f.Name())
		}
	}
	if len(files) == 0 {
		return nil, nil
	}
	return manifest.ManifestsFromFiles(files)
}
