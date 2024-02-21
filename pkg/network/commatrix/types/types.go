package types

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"
)

type ComMatrix struct {
	Matrix []ComDetails
}

type ComDetails struct {
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	Port      string `json:"port"`
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	NodeRole  string `json:"nodeRole"`
	Optional  bool   `json:"optional"`
}

func (m *ComMatrix) ToCSV() ([]byte, error) {
	var header = "direction,protocol,port,namespace,service,pod,container,nodeRole,optional"

	out := make([]byte, 0)
	w := bytes.NewBuffer(out)
	csvwriter := csv.NewWriter(w)

	csvwriter.Write(strings.Split(header, ","))

	for _, cd := range m.Matrix {
		record := strings.Split(cd.String(), ",")
		err := csvwriter.Write(record)
		if err != nil {
			return nil, fmt.Errorf("failed to convert to CSV foramt: %w", err)
		}
	}
	csvwriter.Flush()

	return w.Bytes(), nil
}

func (m *ComMatrix) ToJSON() ([]byte, error) {
	out, err := json.Marshal(m.Matrix)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (m *ComMatrix) ToYAML() ([]byte, error) {
	out, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (m *ComMatrix) String() string {
	var result strings.Builder
	for _, details := range m.Matrix {
		result.WriteString(details.String() + "\n")
	}

	return result.String()
}

func (cd ComDetails) String() string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%v", cd.Direction, cd.Protocol, cd.Port, cd.Namespace, cd.Service, cd.Pod, cd.Container, cd.NodeRole, cd.Optional)
}

func RemoveDups(outPuts []ComDetails) []ComDetails {
	allKeys := make(map[string]bool)
	res := []ComDetails{}
	for _, item := range outPuts {
		str := fmt.Sprintf("%s-%s-%s", item.NodeRole, item.Port, item.Protocol)
		if _, value := allKeys[str]; !value {
			allKeys[str] = true
			res = append(res, item)
		}
	}

	return res
}

// Diff returns the diff ComMatrix.
func (m ComMatrix) Diff(other ComMatrix) ComMatrix {
	diff := []ComDetails{}
	for _, cd1 := range m.Matrix {
		found := false
		strComDetail1 := fmt.Sprintf("%s-%s-%s", cd1.NodeRole, cd1.Port, cd1.Protocol)
		for _, cd2 := range other.Matrix {
			strComDetail2 := fmt.Sprintf("%s-%s-%s", cd2.NodeRole, cd2.Port, cd2.Protocol)
			if strComDetail1 == strComDetail2 {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, cd1)
		}
	}

	return ComMatrix{Matrix: diff}
}
