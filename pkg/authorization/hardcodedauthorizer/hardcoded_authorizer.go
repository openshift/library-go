package hardcodedauthorizer

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

type hardcodedAuthorizer struct {
	usernames sets.String
	rules     []rbacv1.PolicyRule
}

func (h hardcodedAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	if !h.usernames.Has(a.GetUser().GetName()) {
		return authorizer.DecisionNoOpinion, "", nil
	}

	for i := range h.rules {
		if ruleAllows(a, &h.rules[i]) {
			return authorizer.DecisionAllow, "hardcoded rules allow", nil
		}
	}

	return authorizer.DecisionNoOpinion, "", nil
}

// lifted directly from k/k authorizer/rbac/rbac.go
func ruleAllows(requestAttributes authorizer.Attributes, rule *rbacv1.PolicyRule) bool {
	if requestAttributes.IsResourceRequest() {
		combinedResource := requestAttributes.GetResource()
		if len(requestAttributes.GetSubresource()) > 0 {
			combinedResource = requestAttributes.GetResource() + "/" + requestAttributes.GetSubresource()
		}

		return verbMatches(rule, requestAttributes.GetVerb()) &&
			apiGroupMatches(rule, requestAttributes.GetAPIGroup()) &&
			resourceMatches(rule, combinedResource, requestAttributes.GetSubresource()) &&
			resourceNameMatches(rule, requestAttributes.GetName())
	}

	return verbMatches(rule, requestAttributes.GetVerb()) &&
		nonResourceURLMatches(rule, requestAttributes.GetPath())
}

func containsString(haystack []string, needle string) bool {
	for _, val := range haystack {
		if needle == val {
			return true
		}
	}
	return false
}

// NewHardcodedAuthorizer allows a set of named users access to the rules.
// You cannot restrict by namespaces (there's just no field)
func NewHardcodedAuthorizer(rules []rbacv1.PolicyRule, usernames ...string) (authorizer.Authorizer, error) {
	return &hardcodedAuthorizer{
		usernames: sets.NewString(usernames...),
		rules:     rules,
	}, nil
}

func NewHardcodedAuthorizerOrDie(rules []rbacv1.PolicyRule, usernames ...string) authorizer.Authorizer {
	ret, err := NewHardcodedAuthorizer(rules, usernames...)
	if err != nil {
		panic(err)
	}
	return ret
}

// NewHardcodedMetricsScaperAuthorizer provides an authorizer that allows metrics scraping without contacting the
// kube-apiserver for an authorization check on a rule we always have in place.
func NewHardcodedMetricsScaperAuthorizer() authorizer.Authorizer {
	return NewHardcodedAuthorizerOrDie(
		[]rbacv1.PolicyRule{
			NewRule("get").URLs("/metrics").RuleOrDie(),
		},
		"system:serviceaccount:openshift-monitoring:prometheus-k8s")
}
