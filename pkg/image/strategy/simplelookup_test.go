package strategy

import (
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	reference "github.com/openshift/library-go/pkg/image/reference"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func icspFile(t *testing.T) string {
	icspFile, err := ioutil.TempFile("/tmp", "test.*.icsp.yaml")
	if err != nil {
		t.Errorf("error creating test icsp file: %v", err)
	}
	icsp := `
apiVersion: operator.openshift.io/v1alpha1
kind: ImageContentSourcePolicy
metadata:
  name: release
spec:
  repositoryDigestMirrors:
  - mirrors:
    - does.not.exist/match/image
    source: docker.io/ocp-test/does-not-exist
  - mirrors:
    - exists/match/image
    source: quay.io/ocp-test/does-not-exist
`
	err = ioutil.WriteFile(icspFile.Name(), []byte(icsp), 0)
	if err != nil {
		t.Errorf("error wriing to test icsp file: %v", err)
	}
	return icspFile.Name()
}

func TestAlternativeImageSources(t *testing.T) {
	tests := []struct {
		name                 string
		icspList             []operatorv1alpha1.ImageContentSourcePolicy
		icspFile             string
		image                string
		imageSourcesExpected []string
	}{
		{
			name: "multiple ICSPs",
			icspList: []operatorv1alpha1.ImageContentSourcePolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "release",
					},
					Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
						RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
							{
								Source: "quay.io/multiple/icsps",
								Mirrors: []string{
									"someregistry/somerepo/release",
								},
							},
							{
								Source: "quay.io/ocp-test/another-release",
								Mirrors: []string{
									"someregistry/repo/does-not-exist",
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "another",
					},
					Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
						RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
							{
								Source: "quay.io/multiple/icsps",
								Mirrors: []string{
									"anotherregistry/anotherrepo/release",
								},
							},
						},
					},
				},
			},
			icspFile:             "",
			image:                "quay.io/multiple/icsps:4.5",
			imageSourcesExpected: []string{"quay.io/multiple/icsps", "someregistry/somerepo/release", "anotherregistry/anotherrepo/release"},
		},
		{
			name:                 "sources match ICSP file",
			icspList:             []operatorv1alpha1.ImageContentSourcePolicy{},
			icspFile:             icspFile(t),
			image:                "quay.io/ocp-test/does-not-exist:4.7",
			imageSourcesExpected: []string{"quay.io/ocp-test/does-not-exist", "exists/match/image"},
		},
		{
			name:                 "no match ICSP file",
			icspList:             []operatorv1alpha1.ImageContentSourcePolicy{},
			icspFile:             icspFile(t),
			image:                "quay.io/passed/image:4.5",
			imageSourcesExpected: []string{"quay.io/passed/image"},
		},
		{
			name: "ICSP mirrors match image",
			icspList: []operatorv1alpha1.ImageContentSourcePolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "release",
					},
					Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
						RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
							{
								Source: "quay.io/ocp-test/release",
								Mirrors: []string{
									"someregistry/mirrors/match",
								},
							},
						},
					},
				},
			},
			icspFile:             "",
			image:                "quay.io/ocp-test/release:4.5",
			imageSourcesExpected: []string{"quay.io/ocp-test/release", "someregistry/mirrors/match"},
		},
		{
			name: "ICSP source matches image",
			icspList: []operatorv1alpha1.ImageContentSourcePolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "release",
					},
					Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
						RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
							{
								Source: "quay.io/source/matches",
								Mirrors: []string{
									"someregistry/somerepo/release",
								},
							},
						},
					},
				},
			},
			icspFile:             "",
			image:                "quay.io/source/matches:4.5",
			imageSourcesExpected: []string{"quay.io/source/matches", "someregistry/somerepo/release"},
		},
		{
			name: "source image matches multiple mirrors",
			icspList: []operatorv1alpha1.ImageContentSourcePolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "release",
					},
					Spec: operatorv1alpha1.ImageContentSourcePolicySpec{
						RepositoryDigestMirrors: []operatorv1alpha1.RepositoryDigestMirrors{
							{
								Source: "quay.io/ocp-test/release",
								Mirrors: []string{
									"someregistry/mirrors/match",
									"quay.io/another/release",
									"quay.io/andanother/release",
								},
							},
						},
					},
				},
			},
			icspFile:             "",
			image:                "quay.io/ocp-test/release:4.5",
			imageSourcesExpected: []string{"quay.io/ocp-test/release", "someregistry/mirrors/match", "quay.io/another/release", "quay.io/andanother/release"},
		},
		{
			name:                 "no ICSP",
			icspList:             nil,
			icspFile:             "",
			image:                "quay.io/ocp-test/release:4.5",
			imageSourcesExpected: []string{"quay.io/ocp-test/release"},
		},
	}
	for _, tt := range tests {
		imageRef, err := reference.Parse(tt.image)
		if err != nil {
			t.Errorf("parsing image reference error = %v", err)
		}
		var expectedRefs []reference.DockerImageReference
		for _, expected := range tt.imageSourcesExpected {
			expectedRef, err := reference.Parse(expected)
			if err != nil {
				t.Errorf("parsing image reference error = %v", err)
			}
			expectedRefs = append(expectedRefs, expectedRef)
		}

		var icspList []operatorv1alpha1.ImageContentSourcePolicy
		altImageSources := &simpleLookupICSP{icspFile: tt.icspFile}
		switch {
		case len(altImageSources.icspFile) > 0:
			icspList, err = altImageSources.addICSPsFromFile()
			if err != nil {
				t.Errorf("add ICSP from file error = %v", err)
			}
		default:
			icspList = tt.icspList
		}
		altSources, err := altImageSources.alternativeImageSources(imageRef, icspList)
		if err != nil {
			t.Errorf("registry client Context error = %v", err)
		}
		if !reflect.DeepEqual(expectedRefs, altSources) {
			t.Errorf("%s: AddAlternativeImageSource got = %v, want %v, diff = %v", tt.name, altSources, expectedRefs, cmp.Diff(altSources, expectedRefs))
		}
	}
}
