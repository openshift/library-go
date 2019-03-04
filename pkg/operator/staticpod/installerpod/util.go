package installerpod

import "fmt"

func nameFor(prefix, revision string) string {
	return fmt.Sprintf("%s-%s", prefix, revision)
}

func prefixFor(name, revision string) string {
	return name[0 : len(name)-len(fmt.Sprintf("-%s", revision))]
}
