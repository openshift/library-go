package assets

import (
	"os"
	"path/filepath"
	"testing"
	"text/template"

	configv1 "github.com/openshift/api/config/v1"
)

func TestAsset_WriteFile(t *testing.T) {
	sampleAssets := Assets{
		{
			Name: "test-default",
			Data: []byte("test"),
		},
		{
			Name:           "test-restricted",
			FilePermission: PermissionFileRestricted,
			Data:           []byte("test"),
		},
		{
			Name:           "test-default-explicit",
			FilePermission: PermissionFileDefault,
			Data:           []byte("test"),
		},
	}

	assetDir, err := os.MkdirTemp("", "asset-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(assetDir)

	if err := sampleAssets.WriteFiles(assetDir); err != nil {
		t.Fatalf("unexpected error when writing files: %v", err)
	}

	if s, err := os.Stat(filepath.Join(assetDir, sampleAssets[0].Name)); err != nil {
		t.Fatalf("expected file to exists, got: %v", err)
	} else {
		if s.Mode() != os.FileMode(PermissionFileDefault) {
			t.Errorf("expected file to have %d permissions, got %d", PermissionFileDefault, s.Mode())
		}
	}

	if s, err := os.Stat(filepath.Join(assetDir, sampleAssets[1].Name)); err != nil {
		t.Fatalf("expected file to exists, got: %v", err)
	} else {
		if s.Mode() != os.FileMode(sampleAssets[1].FilePermission) {
			t.Errorf("expected file to have %d permissions, got %d", sampleAssets[1].FilePermission, s.Mode())
		}
	}

	if s, err := os.Stat(filepath.Join(assetDir, sampleAssets[2].Name)); err != nil {
		t.Fatalf("expected file to exists, got: %v", err)
	} else {
		if s.Mode() != os.FileMode(sampleAssets[2].FilePermission) {
			t.Errorf("expected file to have %s permissions, got %s", os.FileMode(sampleAssets[2].FilePermission), s.Mode())
		}
	}
}

func TestInstallerFeatureSet(t *testing.T) {

	dir, err := os.MkdirTemp("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	testCases := []struct {
		name         string
		NoAnnotation bool
		Annotation   string
		shouldMatch  []configv1.FeatureSet
	}{
		{
			name:         "NoAnnotation",
			NoAnnotation: true,
			shouldMatch:  []configv1.FeatureSet{configv1.Default, configv1.DevPreviewNoUpgrade, configv1.TechPreviewNoUpgrade, configv1.CustomNoUpgrade},
		},
		{
			name:        "EmptyAnnotation",
			Annotation:  "",
			shouldMatch: []configv1.FeatureSet{configv1.Default, configv1.DevPreviewNoUpgrade, configv1.TechPreviewNoUpgrade, configv1.CustomNoUpgrade},
		},
		{
			name:        "Default",
			Annotation:  "Default",
			shouldMatch: []configv1.FeatureSet{configv1.Default},
		},
		{
			name:        "TechPreviewNoUpgrade",
			Annotation:  "TechPreviewNoUpgrade",
			shouldMatch: []configv1.FeatureSet{configv1.TechPreviewNoUpgrade},
		},
		{
			name:        "CustomNoUpgrade",
			Annotation:  "CustomNoUpgrade",
			shouldMatch: []configv1.FeatureSet{configv1.CustomNoUpgrade},
		},
		{
			name:        "DevPreviewNoUpgrade",
			Annotation:  "DevPreviewNoUpgrade",
			shouldMatch: []configv1.FeatureSet{configv1.DevPreviewNoUpgrade},
		},
		{
			name:        "UnknownFeatureSet",
			Annotation:  "SelfAware",
			shouldMatch: []configv1.FeatureSet{},
		},
		{
			name:        "Multiple",
			Annotation:  "DevPreviewNoUpgrade,TechPreviewNoUpgrade",
			shouldMatch: []configv1.FeatureSet{configv1.DevPreviewNoUpgrade, configv1.TechPreviewNoUpgrade},
		},
		{
			name:        "MultipleWithEmpty",
			Annotation:  "DevPreviewNoUpgrade,,TechPreviewNoUpgrade",
			shouldMatch: []configv1.FeatureSet{configv1.DevPreviewNoUpgrade, configv1.TechPreviewNoUpgrade},
		},
		{
			name:        "MultipleWithUnknown",
			Annotation:  "CustomNoUpgrade,SelfAware,TechPreviewNoUpgrade",
			shouldMatch: []configv1.FeatureSet{configv1.CustomNoUpgrade, configv1.TechPreviewNoUpgrade},
		},
	}

	tmpl, err := template.New("test").Parse("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n" +
		"{{ if not .NoAnnotation }}  annotations:\n    \"release.openshift.io/feature-set\": \"{{.Annotation}}\"\n{{end}}")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, err := os.CreateTemp(dir, "*.yaml")
			if err != nil {
				t.Fatal(err)
			}
			if err := tmpl.Execute(manifest, tc); err != nil {
				_ = manifest.Close()
				t.Fatal(err)
			}
			manifest.Close()
			content, err := os.ReadFile(manifest.Name())
			if err != nil {
				t.Fatal(err)
			}
			for _, fs := range []configv1.FeatureSet{configv1.Default, configv1.DevPreviewNoUpgrade, configv1.TechPreviewNoUpgrade, configv1.CustomNoUpgrade} {

				var shouldMatch bool
				for _, i := range tc.shouldMatch {
					if i == fs {
						shouldMatch = true
						break
					}
				}

				match, err := InstallerFeatureSet(string(fs))(content)
				if err != nil {
					t.Fatal(err)
				}
				if match == shouldMatch {
					continue
				}
				if fs == configv1.Default {
					fs = "Default"
				}
				t.Errorf("%s: should match: %v, match: %v", fs, shouldMatch, match)
			}
		})
	}
}
