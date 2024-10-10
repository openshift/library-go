package manifestclient

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

type SerializedRequestish interface {
	GetSerializedRequest() *SerializedRequest
	SuggestedFilenames() (string, string)
	DeepCopy() SerializedRequestish
}

type FileOriginatedSerializedRequest struct {
	BodyFilename    string
	OptionsFilename string

	SerializedRequest SerializedRequest
}

type TrackedSerializedRequest struct {
	RequestNumber int

	SerializedRequest SerializedRequest
}

type SerializedRequest struct {
	Action       Action
	ResourceType schema.GroupVersionResource
	KindType     schema.GroupVersionKind
	Namespace    string
	Name         string

	Options []byte
	Body    []byte
}

// Difference returns a set of objects that are not in s2.
// For example:
// s1 = {a1, a2, a3}
// s2 = {a1, a2, a4, a5}
// s1.Difference(s2) = {a3}
// s2.Difference(s1) = {a4, a5}
func DifferenceOfSerializedRequests[S ~[]E, E SerializedRequestish, T ~[]F, F SerializedRequestish](lhs S, rhs T) S {
	ret := S{}

	for i, currLHS := range lhs {
		found := false
		for _, currRHS := range rhs {
			if EquivalentSerializedRequests(currLHS, currRHS) {
				found = true
				break
			}
		}
		if !found {
			ret = append(ret, lhs[i])
		}
	}
	return ret
}

func AreAllSerializedRequestsEquivalent[S ~[]E, E SerializedRequestish, T ~[]F, F SerializedRequestish](lhs S, rhs T) bool {
	if len(DifferenceOfSerializedRequests(lhs, rhs)) != 0 {
		return false
	}
	if len(DifferenceOfSerializedRequests(rhs, lhs)) != 0 {
		return false
	}
	return true
}

func EquivalentSerializedRequests(lhs, rhs SerializedRequestish) bool {
	return lhs.GetSerializedRequest().Equals(rhs.GetSerializedRequest())
}

func MakeFilenameGoModSafe(in string) string {
	// go mod doesn't like colons, so rename those.  We might theoretically conflict, but we shouldn't practically do so often
	return strings.Replace(in, ":", "-COLON-", -1)
}

func (lhs *FileOriginatedSerializedRequest) Equals(rhs *FileOriginatedSerializedRequest) bool {
	return CompareFileOriginatedSerializedRequest(lhs, rhs) == 0
}

func CompareFileOriginatedSerializedRequest(lhs, rhs *FileOriginatedSerializedRequest) int {
	switch {
	case lhs == nil && rhs == nil:
		return 0
	case lhs == nil && rhs != nil:
		return 1
	case lhs != nil && rhs == nil:
		return -1
	}

	if cmp := CompareSerializedRequest(&lhs.SerializedRequest, &rhs.SerializedRequest); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(lhs.BodyFilename, rhs.BodyFilename); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(lhs.OptionsFilename, rhs.OptionsFilename); cmp != 0 {
		return cmp
	}

	return 0
}

func (lhs *TrackedSerializedRequest) Equals(rhs *TrackedSerializedRequest) bool {
	return CompareTrackedSerializedRequest(lhs, rhs) == 0
}

func CompareTrackedSerializedRequest(lhs, rhs *TrackedSerializedRequest) int {
	switch {
	case lhs == nil && rhs == nil:
		return 0
	case lhs == nil && rhs != nil:
		return 1
	case lhs != nil && rhs == nil:
		return -1
	}

	if lhs.RequestNumber < rhs.RequestNumber {
		return -1
	} else if lhs.RequestNumber > rhs.RequestNumber {
		return 1
	}

	return CompareSerializedRequest(&lhs.SerializedRequest, &rhs.SerializedRequest)
}

func (lhs *SerializedRequest) Equals(rhs *SerializedRequest) bool {
	return CompareSerializedRequest(lhs, rhs) == 0
}

func CompareSerializedRequest(lhs, rhs *SerializedRequest) int {
	switch {
	case lhs == nil && rhs == nil:
		return 0
	case lhs == nil && rhs != nil:
		return 1
	case lhs != nil && rhs == nil:
		return -1
	}

	if cmp := strings.Compare(string(lhs.Action), string(rhs.Action)); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(lhs.ResourceType.Group, rhs.ResourceType.Group); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(lhs.ResourceType.Version, rhs.ResourceType.Version); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(lhs.ResourceType.Resource, rhs.ResourceType.Resource); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(lhs.KindType.Group, rhs.KindType.Group); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(lhs.KindType.Version, rhs.KindType.Version); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(lhs.KindType.Kind, rhs.KindType.Kind); cmp != 0 {
		return cmp
	}

	if cmp := strings.Compare(lhs.Namespace, rhs.Namespace); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(lhs.Name, rhs.Name); cmp != 0 {
		return cmp
	}

	if cmp := bytes.Compare(lhs.Body, rhs.Body); cmp != 0 {
		return cmp
	}
	if cmp := bytes.Compare(lhs.Options, rhs.Options); cmp != 0 {
		return cmp
	}

	return 0
}

func (a FileOriginatedSerializedRequest) GetSerializedRequest() *SerializedRequest {
	return &a.SerializedRequest
}

func (a TrackedSerializedRequest) GetSerializedRequest() *SerializedRequest {
	return &a.SerializedRequest
}

func (a SerializedRequest) GetSerializedRequest() *SerializedRequest {
	return &a
}

func (a FileOriginatedSerializedRequest) SuggestedFilenames() (string, string) {
	return a.BodyFilename, a.OptionsFilename
}

func (a TrackedSerializedRequest) SuggestedFilenames() (string, string) {
	return suggestedFilenames(a.SerializedRequest, a.RequestNumber)
}

func (a SerializedRequest) SuggestedFilenames() (string, string) {
	// this may very well conflict in some cases. Up to the caller to work out how to fix it.
	uniqueNumber := 0 // chosen by fair dice roll. guaranteed to be random. :)
	return suggestedFilenames(a, uniqueNumber)
}

func suggestedFilenames(a SerializedRequest, uniqueNumber int) (string, string) {
	groupName := a.ResourceType.Group
	if len(groupName) == 0 {
		groupName = "core"
	}

	scopingString := ""
	if len(a.Namespace) > 0 {
		scopingString = filepath.Join("namespaces", a.Namespace)
	} else {
		scopingString = filepath.Join("cluster-scoped")
	}

	bodyFilename := MakeFilenameGoModSafe(
		filepath.Join(
			string(a.Action),
			scopingString,
			groupName,
			a.ResourceType.Resource,
			fmt.Sprintf("%03d-body-%s.yaml", uniqueNumber, a.Name),
		),
	)
	optionsFilename := ""
	if len(a.Options) > 0 {
		optionsFilename = MakeFilenameGoModSafe(
			filepath.Join(
				string(a.Action),
				scopingString,
				groupName,
				a.ResourceType.Resource,
				fmt.Sprintf("%03d-options-%s.yaml", uniqueNumber, a.Name),
			),
		)
	}
	return bodyFilename, optionsFilename
}

func (a FileOriginatedSerializedRequest) DeepCopy() SerializedRequestish {
	return FileOriginatedSerializedRequest{
		BodyFilename:      a.BodyFilename,
		OptionsFilename:   a.OptionsFilename,
		SerializedRequest: a.SerializedRequest.DeepCopy().(SerializedRequest),
	}
}

func (a TrackedSerializedRequest) DeepCopy() SerializedRequestish {
	return TrackedSerializedRequest{
		RequestNumber:     a.RequestNumber,
		SerializedRequest: a.SerializedRequest.DeepCopy().(SerializedRequest),
	}
}

func (a SerializedRequest) DeepCopy() SerializedRequestish {
	return SerializedRequest{
		Action:       a.Action,
		ResourceType: a.ResourceType,
		KindType:     a.KindType,
		Namespace:    a.Namespace,
		Name:         a.Name,
		Options:      bytes.Clone(a.Options),
		Body:         bytes.Clone(a.Body),
	}
}
