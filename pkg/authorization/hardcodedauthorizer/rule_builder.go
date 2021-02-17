package hardcodedauthorizer

import (
	"fmt"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
)

// copied from k/k

// PolicyRuleBuilder let's us attach methods.  A no-no for API types.
// We use it to construct rules in code.  It's more compact than trying to write them
// out in a literal and allows us to perform some basic checking during construction
type PolicyRuleBuilder struct {
	PolicyRule rbacv1.PolicyRule
}

func NewRule(verbs ...string) *PolicyRuleBuilder {
	return &PolicyRuleBuilder{
		PolicyRule: rbacv1.PolicyRule{Verbs: verbs},
	}
}

func (r *PolicyRuleBuilder) Groups(groups ...string) *PolicyRuleBuilder {
	r.PolicyRule.APIGroups = append(r.PolicyRule.APIGroups, groups...)
	return r
}

func (r *PolicyRuleBuilder) Resources(resources ...string) *PolicyRuleBuilder {
	r.PolicyRule.Resources = append(r.PolicyRule.Resources, resources...)
	return r
}

func (r *PolicyRuleBuilder) Names(names ...string) *PolicyRuleBuilder {
	r.PolicyRule.ResourceNames = append(r.PolicyRule.ResourceNames, names...)
	return r
}

func (r *PolicyRuleBuilder) URLs(urls ...string) *PolicyRuleBuilder {
	r.PolicyRule.NonResourceURLs = append(r.PolicyRule.NonResourceURLs, urls...)
	return r
}

func (r *PolicyRuleBuilder) RuleOrDie() rbacv1.PolicyRule {
	ret, err := r.Rule()
	if err != nil {
		panic(err)
	}
	return ret
}

func (r *PolicyRuleBuilder) Rule() (rbacv1.PolicyRule, error) {
	if len(r.PolicyRule.Verbs) == 0 {
		return rbacv1.PolicyRule{}, fmt.Errorf("verbs are required: %#v", r.PolicyRule)
	}

	switch {
	case len(r.PolicyRule.NonResourceURLs) > 0:
		if len(r.PolicyRule.APIGroups) != 0 || len(r.PolicyRule.Resources) != 0 || len(r.PolicyRule.ResourceNames) != 0 {
			return rbacv1.PolicyRule{}, fmt.Errorf("non-resource rule may not have apiGroups, resources, or resourceNames: %#v", r.PolicyRule)
		}
	case len(r.PolicyRule.Resources) > 0:
		if len(r.PolicyRule.NonResourceURLs) != 0 {
			return rbacv1.PolicyRule{}, fmt.Errorf("resource rule may not have nonResourceURLs: %#v", r.PolicyRule)
		}
		if len(r.PolicyRule.APIGroups) == 0 {
			// this a common bug
			return rbacv1.PolicyRule{}, fmt.Errorf("resource rule must have apiGroups: %#v", r.PolicyRule)
		}
	default:
		return rbacv1.PolicyRule{}, fmt.Errorf("a rule must have either nonResourceURLs or resources: %#v", r.PolicyRule)
	}

	sort.Strings(r.PolicyRule.Resources)
	sort.Strings(r.PolicyRule.ResourceNames)
	sort.Strings(r.PolicyRule.APIGroups)
	sort.Strings(r.PolicyRule.NonResourceURLs)
	sort.Strings(r.PolicyRule.Verbs)
	return r.PolicyRule, nil
}
