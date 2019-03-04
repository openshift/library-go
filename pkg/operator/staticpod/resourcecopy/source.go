package resourcecopy

type Source interface {
	Name() string
	Namespace() string
	IsOptional() bool
}

type DefaultSource struct {
	name           string
	namespace      string
	isOptional     bool
	nameMutationFn func(string) string
}

func NewSource(namespace, name string) Source {
	return &DefaultSource{namespace: namespace, name: name}
}

func NewOptionalSource(namespace, name string) Source {
	return &DefaultSource{namespace: namespace, name: name, isOptional: true}
}

func NewSourceWithMutation(namespace, name string, mutationFn func(string) string) Source {
	return &DefaultSource{namespace: namespace, name: name, nameMutationFn: mutationFn}
}

func NewOptionalSourceWithMutation(namespace, name string, mutationFn func(string) string) Source {
	return &DefaultSource{namespace: namespace, name: name, nameMutationFn: mutationFn, isOptional: true}
}

func (s *DefaultSource) Namespace() string {
	return s.namespace
}

func (s *DefaultSource) Name() string {
	if s.nameMutationFn == nil {
		return s.name
	}
	return s.nameMutationFn(s.name)
}

func (s *DefaultSource) IsOptional() bool {
	return s.isOptional
}
