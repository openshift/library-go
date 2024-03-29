package naming

import (
	"math/rand"
	"testing"

	kvalidation "k8s.io/apimachinery/pkg/util/validation"
)

func TestGetName(t *testing.T) {
	for i := 0; i < 10; i++ {
		shortName := randSeq(rand.Intn(kvalidation.DNS1123SubdomainMaxLength-1) + 1)
		shortNameForDeploy := randSeq(rand.Intn(kvalidation.DNS1123SubdomainMaxLength-len("-deploy")-1) + 1)
		shortNameLongerThan9 := randSeq(rand.Intn(kvalidation.DNS1123SubdomainMaxLength-10) + 10)
		mediumName := randSeq(kvalidation.DNS1123SubdomainMaxLength - 10)
		longName := randSeq(kvalidation.DNS1123SubdomainMaxLength + rand.Intn(100))

		tests := []struct {
			base, suffix, expected string
		}{
			{
				base:     shortNameForDeploy,
				suffix:   "deploy",
				expected: shortNameForDeploy + "-deploy",
			},
			{
				base:     longName,
				suffix:   "deploy",
				expected: longName[:kvalidation.DNS1123SubdomainMaxLength-16] + "-" + hash(longName) + "-deploy",
			},
			{
				base:     shortName,
				suffix:   longName,
				expected: shortName[0:min(len(shortName), kvalidation.DNS1123SubdomainMaxLength-9)] + "-" + hash(shortName+"-"+longName),
			},
			{
				base:     shortNameLongerThan9,
				suffix:   mediumName,
				expected: shortNameLongerThan9[0:min(len(shortNameLongerThan9), kvalidation.DNS1123SubdomainMaxLength-9)] + "-" + hash(shortNameLongerThan9+"-"+mediumName),
			},
			{
				base:     "",
				suffix:   shortName,
				expected: "-" + shortName,
			},
			{
				base:     "",
				suffix:   longName,
				expected: "-" + hash("-"+longName),
			},
			{
				base:     shortName,
				suffix:   "",
				expected: shortName + "-",
			},
			{
				base:     longName,
				suffix:   "",
				expected: longName[:kvalidation.DNS1123SubdomainMaxLength-10] + "-" + hash(longName) + "-",
			},
		}

		for _, test := range tests {
			result := GetName(test.base, test.suffix, kvalidation.DNS1123SubdomainMaxLength)
			if result != test.expected {
				t.Errorf("Got unexpected result. Expected: %s Got: %s", test.expected, result)
			}
		}
	}
}

func TestGetNameIsDifferent(t *testing.T) {
	shortName := randSeq(32)
	deployerName := GetName(shortName, "deploy", kvalidation.DNS1123SubdomainMaxLength)
	builderName := GetName(shortName, "build", kvalidation.DNS1123SubdomainMaxLength)
	if deployerName == builderName {
		t.Errorf("Expecting names to be different: %s\n", deployerName)
	}
	longName := randSeq(kvalidation.DNS1123SubdomainMaxLength + 10)
	deployerName = GetName(longName, "deploy", kvalidation.DNS1123SubdomainMaxLength)
	builderName = GetName(longName, "build", kvalidation.DNS1123SubdomainMaxLength)
	if deployerName == builderName {
		t.Errorf("Expecting names to be different: %s\n", deployerName)
	}
}

func TestGetNameReturnShortNames(t *testing.T) {
	base := randSeq(32)
	for maxLength := 0; maxLength < len(base)+2; maxLength++ {
		for suffixLen := 0; suffixLen <= maxLength+1; suffixLen++ {
			suffix := randSeq(suffixLen)
			got := GetName(base, suffix, maxLength)
			if len(got) > maxLength {
				t.Fatalf("len(GetName(%[1]q, %[2]q, %[3]d)) = len(%[4]q) = %[5]d; want %[3]d", base, suffix, maxLength, got, len(got))
			}
		}
	}
}

// From k8s.io/kubernetes/pkg/api/generator.go
var letters = []rune("abcdefghijklmnopqrstuvwxyz0123456789-")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
