package hardcodedauthorizer

import (
	"context"
	"fmt"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func newRule(verbs, apiGroups, resources, nonResourceURLs string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{
		Verbs:           strings.Split(verbs, ","),
		APIGroups:       strings.Split(apiGroups, ","),
		Resources:       strings.Split(resources, ","),
		NonResourceURLs: strings.Split(nonResourceURLs, ","),
	}
}

type defaultAttributes struct {
	user        string
	groups      string
	verb        string
	resource    string
	subresource string
	namespace   string
	apiGroup    string
}

func (d *defaultAttributes) String() string {
	return fmt.Sprintf("user=(%s), groups=(%s), verb=(%s), resource=(%s), namespace=(%s), apiGroup=(%s)",
		d.user, strings.Split(d.groups, ","), d.verb, d.resource, d.namespace, d.apiGroup)
}

func (d *defaultAttributes) GetUser() user.Info {
	return &user.DefaultInfo{Name: d.user, Groups: strings.Split(d.groups, ",")}
}
func (d *defaultAttributes) GetVerb() string         { return d.verb }
func (d *defaultAttributes) IsReadOnly() bool        { return d.verb == "get" || d.verb == "watch" }
func (d *defaultAttributes) GetNamespace() string    { return d.namespace }
func (d *defaultAttributes) GetResource() string     { return d.resource }
func (d *defaultAttributes) GetSubresource() string  { return d.subresource }
func (d *defaultAttributes) GetName() string         { return "" }
func (d *defaultAttributes) GetAPIGroup() string     { return d.apiGroup }
func (d *defaultAttributes) GetAPIVersion() string   { return "" }
func (d *defaultAttributes) IsResourceRequest() bool { return true }
func (d *defaultAttributes) GetPath() string         { return "" }

func TestAuthorizer(t *testing.T) {
	tests := []struct {
		name       string
		authorizer authorizer.Authorizer

		shouldPass []authorizer.Attributes
		shouldFail []authorizer.Attributes
	}{
		{
			name: "Non-resource-url tests",
			authorizer: NewHardcodedAuthorizerOrDie(
				[]rbacv1.PolicyRule{
					newRule("get", "", "", "/apis"),
				},
				"non-resource-url-getter"),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-url-getter"}, Verb: "get", Path: "/apis"},
			},
			shouldFail: []authorizer.Attributes{
				// wrong user
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "other"}, Verb: "get", Path: "/apis"},
				// wrong verb
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-url-getter"}, Verb: "update", Path: "/apis"},

				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-url-getter"}, Verb: "get", Path: "/apis/foo"},
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-url-getter"}, Verb: "get", Path: "/api"},
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-url-getter"}, Verb: "get", Path: "/apismore"},
			},
		},
		{
			name: "Non-resource-url tests with star verb",
			authorizer: NewHardcodedAuthorizerOrDie(
				[]rbacv1.PolicyRule{
					newRule("*", "", "", "/apis"),
				},
				"non-resource-url"),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-url"}, Verb: "get", Path: "/apis"},
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-url"}, Verb: "watch", Path: "/apis"},
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-url"}, Verb: "update", Path: "/apis"},
			},
			shouldFail: []authorizer.Attributes{},
		},
		{
			name: "Non-resource-url tests with star pattern",
			authorizer: NewHardcodedAuthorizerOrDie(
				[]rbacv1.PolicyRule{
					newRule("*", "", "", "/apis/*"),
				},
				"non-resource-prefix"),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-prefix"}, Verb: "get", Path: "/apis/v1"},
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-prefix"}, Verb: "get", Path: "/apis/v1/foobar"},
			},
			shouldFail: []authorizer.Attributes{
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-prefix"}, Verb: "get", Path: "/api/v1"},
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "non-resource-prefix"}, Verb: "get", Path: "/metrics"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, attr := range tt.shouldPass {
				if decision, _, _ := tt.authorizer.Authorize(context.Background(), attr); decision != authorizer.DecisionAllow {
					t.Errorf("incorrectly restricted %s", attr)
				}
			}

			for _, attr := range tt.shouldFail {
				if decision, _, _ := tt.authorizer.Authorize(context.Background(), attr); decision == authorizer.DecisionAllow {
					t.Errorf("incorrectly passed %s", attr)
				}
			}
		})
	}
}

func TestRuleMatches(t *testing.T) {
	tests := []struct {
		name string
		rule rbacv1.PolicyRule

		requestsToExpected map[authorizer.AttributesRecord]bool
	}{
		{
			name: "star verb, exact match other",
			rule: NewRule("*").Groups("group1").Resources("resource1").RuleOrDie(),
			requestsToExpected: map[authorizer.AttributesRecord]bool{
				resourceRequest("verb1").Group("group1").Resource("resource1").New(): true,
				resourceRequest("verb1").Group("group2").Resource("resource1").New(): false,
				resourceRequest("verb1").Group("group1").Resource("resource2").New(): false,
				resourceRequest("verb1").Group("group2").Resource("resource2").New(): false,
				resourceRequest("verb2").Group("group1").Resource("resource1").New(): true,
				resourceRequest("verb2").Group("group2").Resource("resource1").New(): false,
				resourceRequest("verb2").Group("group1").Resource("resource2").New(): false,
				resourceRequest("verb2").Group("group2").Resource("resource2").New(): false,
			},
		},
		{
			name: "star group, exact match other",
			rule: NewRule("verb1").Groups("*").Resources("resource1").RuleOrDie(),
			requestsToExpected: map[authorizer.AttributesRecord]bool{
				resourceRequest("verb1").Group("group1").Resource("resource1").New(): true,
				resourceRequest("verb1").Group("group2").Resource("resource1").New(): true,
				resourceRequest("verb1").Group("group1").Resource("resource2").New(): false,
				resourceRequest("verb1").Group("group2").Resource("resource2").New(): false,
				resourceRequest("verb2").Group("group1").Resource("resource1").New(): false,
				resourceRequest("verb2").Group("group2").Resource("resource1").New(): false,
				resourceRequest("verb2").Group("group1").Resource("resource2").New(): false,
				resourceRequest("verb2").Group("group2").Resource("resource2").New(): false,
			},
		},
		{
			name: "star resource, exact match other",
			rule: NewRule("verb1").Groups("group1").Resources("*").RuleOrDie(),
			requestsToExpected: map[authorizer.AttributesRecord]bool{
				resourceRequest("verb1").Group("group1").Resource("resource1").New(): true,
				resourceRequest("verb1").Group("group2").Resource("resource1").New(): false,
				resourceRequest("verb1").Group("group1").Resource("resource2").New(): true,
				resourceRequest("verb1").Group("group2").Resource("resource2").New(): false,
				resourceRequest("verb2").Group("group1").Resource("resource1").New(): false,
				resourceRequest("verb2").Group("group2").Resource("resource1").New(): false,
				resourceRequest("verb2").Group("group1").Resource("resource2").New(): false,
				resourceRequest("verb2").Group("group2").Resource("resource2").New(): false,
			},
		},
		{
			name: "tuple expansion",
			rule: NewRule("verb1", "verb2").Groups("group1", "group2").Resources("resource1", "resource2").RuleOrDie(),
			requestsToExpected: map[authorizer.AttributesRecord]bool{
				resourceRequest("verb1").Group("group1").Resource("resource1").New(): true,
				resourceRequest("verb1").Group("group2").Resource("resource1").New(): true,
				resourceRequest("verb1").Group("group1").Resource("resource2").New(): true,
				resourceRequest("verb1").Group("group2").Resource("resource2").New(): true,
				resourceRequest("verb2").Group("group1").Resource("resource1").New(): true,
				resourceRequest("verb2").Group("group2").Resource("resource1").New(): true,
				resourceRequest("verb2").Group("group1").Resource("resource2").New(): true,
				resourceRequest("verb2").Group("group2").Resource("resource2").New(): true,
			},
		},
		{
			name: "subresource expansion",
			rule: NewRule("*").Groups("*").Resources("resource1/subresource1").RuleOrDie(),
			requestsToExpected: map[authorizer.AttributesRecord]bool{
				resourceRequest("verb1").Group("group1").Resource("resource1").Subresource("subresource1").New(): true,
				resourceRequest("verb1").Group("group2").Resource("resource1").Subresource("subresource2").New(): false,
				resourceRequest("verb1").Group("group1").Resource("resource2").Subresource("subresource1").New(): false,
				resourceRequest("verb1").Group("group2").Resource("resource2").Subresource("subresource1").New(): false,
				resourceRequest("verb2").Group("group1").Resource("resource1").Subresource("subresource1").New(): true,
				resourceRequest("verb2").Group("group2").Resource("resource1").Subresource("subresource2").New(): false,
				resourceRequest("verb2").Group("group1").Resource("resource2").Subresource("subresource1").New(): false,
				resourceRequest("verb2").Group("group2").Resource("resource2").Subresource("subresource1").New(): false,
			},
		},
		{
			name: "star nonresource, exact match other",
			rule: NewRule("verb1").URLs("*").RuleOrDie(),
			requestsToExpected: map[authorizer.AttributesRecord]bool{
				nonresourceRequest("verb1").URL("/foo").New():         true,
				nonresourceRequest("verb1").URL("/foo/bar").New():     true,
				nonresourceRequest("verb1").URL("/foo/baz").New():     true,
				nonresourceRequest("verb1").URL("/foo/bar/one").New(): true,
				nonresourceRequest("verb1").URL("/foo/baz/one").New(): true,
				nonresourceRequest("verb2").URL("/foo").New():         false,
				nonresourceRequest("verb2").URL("/foo/bar").New():     false,
				nonresourceRequest("verb2").URL("/foo/baz").New():     false,
				nonresourceRequest("verb2").URL("/foo/bar/one").New(): false,
				nonresourceRequest("verb2").URL("/foo/baz/one").New(): false,
			},
		},
		{
			name: "star nonresource subpath",
			rule: NewRule("verb1").URLs("/foo/*").RuleOrDie(),
			requestsToExpected: map[authorizer.AttributesRecord]bool{
				nonresourceRequest("verb1").URL("/foo").New():            false,
				nonresourceRequest("verb1").URL("/foo/bar").New():        true,
				nonresourceRequest("verb1").URL("/foo/baz").New():        true,
				nonresourceRequest("verb1").URL("/foo/bar/one").New():    true,
				nonresourceRequest("verb1").URL("/foo/baz/one").New():    true,
				nonresourceRequest("verb1").URL("/notfoo").New():         false,
				nonresourceRequest("verb1").URL("/notfoo/bar").New():     false,
				nonresourceRequest("verb1").URL("/notfoo/baz").New():     false,
				nonresourceRequest("verb1").URL("/notfoo/bar/one").New(): false,
				nonresourceRequest("verb1").URL("/notfoo/baz/one").New(): false,
			},
		},
		{
			name: "star verb, exact nonresource",
			rule: NewRule("*").URLs("/foo", "/foo/bar/one").RuleOrDie(),
			requestsToExpected: map[authorizer.AttributesRecord]bool{
				nonresourceRequest("verb1").URL("/foo").New():         true,
				nonresourceRequest("verb1").URL("/foo/bar").New():     false,
				nonresourceRequest("verb1").URL("/foo/baz").New():     false,
				nonresourceRequest("verb1").URL("/foo/bar/one").New(): true,
				nonresourceRequest("verb1").URL("/foo/baz/one").New(): false,
				nonresourceRequest("verb2").URL("/foo").New():         true,
				nonresourceRequest("verb2").URL("/foo/bar").New():     false,
				nonresourceRequest("verb2").URL("/foo/baz").New():     false,
				nonresourceRequest("verb2").URL("/foo/bar/one").New(): true,
				nonresourceRequest("verb2").URL("/foo/baz/one").New(): false,
			},
		},
	}
	for _, tc := range tests {
		for request, expected := range tc.requestsToExpected {
			if e, a := expected, ruleAllows(request, &tc.rule); e != a {
				t.Errorf("%q: expected %v, got %v for %v", tc.name, e, a, request)
			}
		}
	}
}

type requestAttributeBuilder struct {
	request authorizer.AttributesRecord
}

func resourceRequest(verb string) *requestAttributeBuilder {
	return &requestAttributeBuilder{
		request: authorizer.AttributesRecord{ResourceRequest: true, Verb: verb},
	}
}

func nonresourceRequest(verb string) *requestAttributeBuilder {
	return &requestAttributeBuilder{
		request: authorizer.AttributesRecord{ResourceRequest: false, Verb: verb},
	}
}

func (r *requestAttributeBuilder) Group(group string) *requestAttributeBuilder {
	r.request.APIGroup = group
	return r
}

func (r *requestAttributeBuilder) Resource(resource string) *requestAttributeBuilder {
	r.request.Resource = resource
	return r
}

func (r *requestAttributeBuilder) Subresource(subresource string) *requestAttributeBuilder {
	r.request.Subresource = subresource
	return r
}

func (r *requestAttributeBuilder) Name(name string) *requestAttributeBuilder {
	r.request.Name = name
	return r
}

func (r *requestAttributeBuilder) URL(url string) *requestAttributeBuilder {
	r.request.Path = url
	return r
}

func (r *requestAttributeBuilder) New() authorizer.AttributesRecord {
	return r.request
}
