package imageutil

import (
	"reflect"
	"testing"

	imagev1 "github.com/openshift/api/image/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestJoinImageStreamTag(t *testing.T) {
	if e, a := "foo:bar", JoinImageStreamTag("foo", "bar"); e != a {
		t.Errorf("Unexpected value: %s", a)
	}
	if e, a := "foo:"+DefaultImageTag, JoinImageStreamTag("foo", ""); e != a {
		t.Errorf("Unexpected value: %s", a)
	}
}

func TestParseImageStreamTagName(t *testing.T) {
	tests := map[string]struct {
		id           string
		expectedName string
		expectedTag  string
		expectError  bool
	}{
		"empty id": {
			id:          "",
			expectError: true,
		},
		"missing semicolon": {
			id:          "hello",
			expectError: true,
		},
		"too many semicolons": {
			id:          "a:b:c",
			expectError: true,
		},
		"empty name": {
			id:          ":tag",
			expectError: true,
		},
		"empty tag": {
			id:          "name",
			expectError: true,
		},
		"happy path": {
			id:           "name:tag",
			expectError:  false,
			expectedName: "name",
			expectedTag:  "tag",
		},
	}

	for description, testCase := range tests {
		name, tag, err := ParseImageStreamTagName(testCase.id)
		gotError := err != nil
		if e, a := testCase.expectError, gotError; e != a {
			t.Fatalf("%s: expected err: %t, got: %t: %s", description, e, a, err)
		}
		if err != nil {
			continue
		}
		if e, a := testCase.expectedName, name; e != a {
			t.Errorf("%s: name: expected %q, got %q", description, e, a)
		}
		if e, a := testCase.expectedTag, tag; e != a {
			t.Errorf("%s: tag: expected %q, got %q", description, e, a)
		}
	}
}

func TestParseImageStreamImageName(t *testing.T) {
	tests := map[string]struct {
		input        string
		expectedRepo string
		expectedId   string
		expectError  bool
	}{
		"empty string": {
			input:       "",
			expectError: true,
		},
		"one part": {
			input:       "a",
			expectError: true,
		},
		"more than 2 parts": {
			input:       "a@b@c",
			expectError: true,
		},
		"empty name part": {
			input:       "@id",
			expectError: true,
		},
		"empty id part": {
			input:       "name@",
			expectError: true,
		},
		"valid input": {
			input:        "repo@id",
			expectedRepo: "repo",
			expectedId:   "id",
			expectError:  false,
		},
	}

	for name, test := range tests {
		repo, id, err := ParseImageStreamImageName(test.input)
		didError := err != nil
		if e, a := test.expectError, didError; e != a {
			t.Errorf("%s: expected error=%t, got=%t: %s", name, e, a, err)
			continue
		}
		if test.expectError {
			continue
		}
		if e, a := test.expectedRepo, repo; e != a {
			t.Errorf("%s: repo: expected %q, got %q", name, e, a)
			continue
		}
		if e, a := test.expectedId, id; e != a {
			t.Errorf("%s: id: expected %q, got %q", name, e, a)
			continue
		}
	}
}
func TestPrioritizeTags(t *testing.T) {
	tests := []struct {
		tags     []string
		expected []string
	}{
		{
			tags:     []string{"other", "latest", "v5.5", "5.2.3", "5.5", "v5.3.6-bother", "5.3.6-abba", "5.6"},
			expected: []string{"latest", "5.6", "5.5", "v5.5", "v5.3.6-bother", "5.3.6-abba", "5.2.3", "other"},
		},
		{
			tags:     []string{"1.1-beta1", "1.2-rc1", "1.1-rc1", "1.1-beta2", "1.2-beta1", "1.2-alpha1", "1.2-beta4", "latest"},
			expected: []string{"latest", "1.2-rc1", "1.2-beta4", "1.2-beta1", "1.2-alpha1", "1.1-rc1", "1.1-beta2", "1.1-beta1"},
		},
		{
			tags:     []string{"7.1", "v7.1", "7.1.0"},
			expected: []string{"7.1", "v7.1", "7.1.0"},
		},
		{
			tags:     []string{"7.1.0", "v7.1", "7.1"},
			expected: []string{"7.1", "v7.1", "7.1.0"},
		},
	}

	for _, tc := range tests {
		t.Log("sorting", tc.tags)
		PrioritizeTags(tc.tags)
		if !reflect.DeepEqual(tc.tags, tc.expected) {
			t.Errorf("got %v, want %v", tc.tags, tc.expected)
		}
	}
}

func TestResolvePullSpecForTag(t *testing.T) {
	int64p := func(i int64) *int64 {
		return &i
	}

	tests := []struct {
		name string

		stream          *imagev1.ImageStream
		tag             string
		defaultExternal bool
		requireLatest   bool

		wantPullSpec   string
		wantHasNewer   bool
		wantHasStatus  bool
		wantIsTagEmpty bool
		wantErr        func(t *testing.T, err error)
	}{
		{
			tag: "empty",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
			},
			wantErr: func(t *testing.T, err error) {
				if err != ErrNoStreamRepository {
					t.Errorf("unexpected error: %v", err)
				}
			},
		},
		{
			tag: "empty",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
				},
			},
			wantIsTagEmpty: true,
			wantPullSpec:   "registry.test.svc/test/stream1:empty",
		},
		{
			tag: "empty",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
				},
			},
			defaultExternal: true,
			wantIsTagEmpty:  true,
			wantPullSpec:    "registry.test.svc/test/stream1:empty",
		},
		{
			tag: "empty",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository:       "registry.test.svc/test/stream1",
					PublicDockerImageRepository: "registry.test.public/test/stream1",
				},
			},
			defaultExternal: true,
			wantIsTagEmpty:  true,
			wantPullSpec:    "registry.test.public/test/stream1:empty",
		},
		{
			tag: "empty",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository:       "registry.test.svc/test/stream1",
					PublicDockerImageRepository: "registry.test.public/test/stream1",
				},
			},
			defaultExternal: true,
			wantIsTagEmpty:  true,
			wantPullSpec:    "registry.test.public/test/stream1:empty",
		},
		{
			tag: "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.SourceTagReferencePolicy},
							From:            nil,
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
				},
			},
			wantIsTagEmpty: true,
			wantPullSpec:   "registry.test.svc/test/stream1:1",
		},
		{
			tag: "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.SourceTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "ImageStreamTag", Name: "other"},
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
				},
			},
			wantIsTagEmpty: true,
			wantPullSpec:   "registry.test.svc/test/stream1:1",
		},
		{
			name: "image hasn't been imported yet and isn't source policy, must wait for status",
			tag:  "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.LocalTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "ImageStreamTag", Name: "test"},
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
				},
			},
			wantIsTagEmpty: true,
			wantPullSpec:   "registry.test.svc/test/stream1:1",
		},
		{
			name: "image hasn't been imported yet and isn't source policy, must wait for status",
			tag:  "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.LocalTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "DockerImage", Name: "quay.io/test/first:tag"},
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
				},
			},
			wantIsTagEmpty: true,
			wantPullSpec:   "registry.test.svc/test/stream1:1",
		},
		{
			tag: "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.SourceTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "DockerImage", Name: "quay.io/test/first:tag"},
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
				},
			},
			wantPullSpec: "quay.io/test/first:tag",
		},
		{
			name: "newer spec tag returning older",
			tag:  "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.SourceTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "DockerImage", Name: "quay.io/test/first:tag"},
							Generation:      int64p(5),
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
					Tags: []imagev1.NamedTagEventList{
						{
							Tag: "1",
							Items: []imagev1.TagEvent{
								{
									DockerImageReference: "quay.io/test/first:older",
									Generation:           4,
								},
							},
						},
					},
				},
			},
			wantHasStatus: true,
			wantHasNewer:  true,
			wantPullSpec:  "quay.io/test/first:older",
		},
		{
			name: "newer spec tag requiring latest",
			tag:  "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.SourceTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "DockerImage", Name: "quay.io/test/first:tag"},
							Generation:      int64p(5),
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
					Tags: []imagev1.NamedTagEventList{
						{
							Tag: "1",
							Items: []imagev1.TagEvent{
								{
									DockerImageReference: "quay.io/test/first:older",
									Generation:           4,
								},
							},
						},
					},
				},
			},
			requireLatest: true,
			wantHasStatus: false,
			wantPullSpec:  "quay.io/test/first:tag",
		},
		{
			name: "spec tag is same generation",
			tag:  "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.SourceTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "DockerImage", Name: "quay.io/test/first:tag"},
							Generation:      int64p(4),
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
					Tags: []imagev1.NamedTagEventList{
						{
							Tag: "1",
							Items: []imagev1.TagEvent{
								{
									DockerImageReference: "quay.io/test/first:older",
									Generation:           4,
								},
							},
						},
					},
				},
			},
			wantHasStatus: true,
			wantHasNewer:  false,
			wantPullSpec:  "quay.io/test/first:older",
		},
		{
			name: "spec tag is older generation (pushed image)",
			tag:  "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.SourceTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "DockerImage", Name: "quay.io/test/first:tag"},
							Generation:      int64p(4),
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
					Tags: []imagev1.NamedTagEventList{
						{
							Tag: "1",
							Items: []imagev1.TagEvent{
								{
									DockerImageReference: "quay.io/test/first:newer",
									Generation:           5,
								},
							},
						},
					},
				},
			},
			wantHasStatus: true,
			wantPullSpec:  "quay.io/test/first:newer",
		},
		{
			name: "local lookup to sha",
			tag:  "1",
			stream: &imagev1.ImageStream{
				ObjectMeta: metav1.ObjectMeta{Name: "stream1", Namespace: "test"},
				Spec: imagev1.ImageStreamSpec{
					Tags: []imagev1.TagReference{
						{
							Name:            "1",
							ReferencePolicy: imagev1.TagReferencePolicy{Type: imagev1.LocalTagReferencePolicy},
							From:            &corev1.ObjectReference{Kind: "DockerImage", Name: "quay.io/test/first:tag"},
							Generation:      int64p(4),
						},
					},
				},
				Status: imagev1.ImageStreamStatus{
					DockerImageRepository: "registry.test.svc/test/stream1",
					Tags: []imagev1.NamedTagEventList{
						{
							Tag: "1",
							Items: []imagev1.TagEvent{
								{
									DockerImageReference: "quay.io/test/first:newer",
									Image:                "sha256:13897c84ca5715a68feafcce9acf779f35806f42d1fcd37e8a2a5706c075252d",
									Generation:           5,
								},
							},
						},
					},
				},
			},
			wantHasStatus: true,
			wantPullSpec:  "registry.test.svc/test/stream1@sha256:13897c84ca5715a68feafcce9acf779f35806f42d1fcd37e8a2a5706c075252d",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pullSpec, hasNewer, hasStatus, isTagEmpty, err := resolvePullSpecForTag(tt.stream, tt.tag, tt.defaultExternal, tt.requireLatest)
			if (err != nil) != (tt.wantErr != nil) {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr != nil)
			}
			if tt.wantErr != nil {
				tt.wantErr(t, err)
			}
			if pullSpec != tt.wantPullSpec {
				t.Errorf("pullSpec = %v, want %v", pullSpec, tt.wantPullSpec)
			}
			if hasNewer != tt.wantHasNewer {
				t.Errorf("hasNewer = %v, want %v", hasNewer, tt.wantHasNewer)
			}
			if hasStatus != tt.wantHasStatus {
				t.Errorf("hasStatus = %v, want %v", hasStatus, tt.wantHasStatus)
			}
			if isTagEmpty != tt.wantIsTagEmpty {
				t.Errorf("isTagEmpty = %v, want %v", isTagEmpty, tt.wantIsTagEmpty)
			}
		})
	}
}
