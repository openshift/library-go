package resourcecopy

// Source defines a source resource to be copied. The resource must have name, namespace and indicate whether it is optional or not.
type Source interface {
	Name() string
	Namespace() string
	IsOptional() bool
}

// DefaultSource implements the Source interface.
type DefaultSource struct {
	name           string
	namespace      string
	isOptional     bool
	nameMutationFn func(string) string
}

// NewSource return a source for resource identified by namespace and name that is required.
func NewSource(namespace, name string) Source {
	return &DefaultSource{namespace: namespace, name: name}
}

// NewSource return a source for resource identified by namespace and name that is optional.
func NewOptionalSource(namespace, name string) Source {
	return &DefaultSource{namespace: namespace, name: name, isOptional: true}
}

// NewSource return a source for resource identified by namespace, name and name mutation function that is required.
func NewSourceWithMutation(namespace, name string, mutationFn func(string) string) Source {
	return &DefaultSource{namespace: namespace, name: name, nameMutationFn: mutationFn}
}

// NewSource return a source for resource identified by namespace, name and name mutation function that is optional.
func NewOptionalSourceWithMutation(namespace, name string, mutationFn func(string) string) Source {
	return &DefaultSource{namespace: namespace, name: name, nameMutationFn: mutationFn, isOptional: true}
}

// Namespace return the resource namespace.
func (s *DefaultSource) Namespace() string {
	return s.namespace
}

// Namespace return the resource name (with mutation applied if mutation function is set).
func (s *DefaultSource) Name() string {
	if s.nameMutationFn == nil {
		return s.name
	}
	return s.nameMutationFn(s.name)
}

// IsOptional indicates whether the source is optional to copy.
func (s *DefaultSource) IsOptional() bool {
	return s.isOptional
}
