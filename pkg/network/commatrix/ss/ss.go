package ss

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openshift/library-go/pkg/network/commatrix/client"
	"github.com/openshift/library-go/pkg/network/commatrix/consts"
	"github.com/openshift/library-go/pkg/network/commatrix/debug"
	"github.com/openshift/library-go/pkg/network/commatrix/nodes"
	"github.com/openshift/library-go/pkg/network/commatrix/types"
)

const (
	processeNameFieldIdx  = 5
	localAddrPortFieldIdx = 3
	interval              = time.Millisecond * 500
	duration              = time.Second * 5
)

var (
	// TcpSSFilterFn is a function variable in Go that filters entries from the 'ss' command output.
	// It takes an entry from the 'ss' command output and returns true if the entry represents a TCP port in the listening state.
	tcpSSFilterFn = func(s string) bool {
		return strings.Contains(s, "127.0.0") || !strings.Contains(s, "LISTEN")
	}
	// UdpSSFilterFn is a function variable in Go that filters entries from the 'ss' command output.
	// It takes an entry from the 'ss' command output and returns true if the entry represents a UDP port in the listening state.
	udpSSFilterFn = func(s string) bool {
		return strings.Contains(s, "127.0.0") || !strings.Contains(s, "ESTAB")
	}
)

func CreateComDetailsFromNode(cs *client.ClientSet, node *corev1.Node) ([]types.ComDetails, error) {
	debugPod, err := debug.New(cs, node.Name, consts.DefaultDebugNamespace, consts.DefaultDebugPodImage)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := debugPod.Clean()
		if err != nil {
			fmt.Printf("failed cleaning debug pod %s: %v", debugPod, err)
		}
	}()

	ssOutTCP, err := debugPod.ExecWithRetry("ss -anplt", interval, duration)
	if err != nil {
		return nil, err
	}
	ssOutUDP, err := debugPod.ExecWithRetry("ss -anplu", interval, duration)
	if err != nil {
		return nil, err
	}

	ssOutFilteredTCP := filterStrings(tcpSSFilterFn, splitByLines(ssOutTCP))
	ssOutFilteredUDP := filterStrings(udpSSFilterFn, splitByLines(ssOutUDP))

	tcpComDetails, err := toComDetails(ssOutFilteredTCP, "TCP", node)
	if err != nil {
		return nil, err
	}
	udpComDetails, err := toComDetails(ssOutFilteredUDP, "UDP", node)
	if err != nil {
		return nil, err
	}

	res := []types.ComDetails{}
	res = append(res, udpComDetails...)
	res = append(res, tcpComDetails...)

	return res, nil
}

func splitByLines(bytes []byte) []string {
	str := string(bytes)
	return strings.Split(str, "\n")
}

func toComDetails(ssOutput []string, protocol string, node *corev1.Node) ([]types.ComDetails, error) {
	res := make([]types.ComDetails, 0)
	nodeRoles := nodes.GetRoles(node)

	for _, ssEntry := range ssOutput {
		cd, err := parseComDetail(ssEntry)
		if err != nil {
			return nil, err
		}
		cd.Protocol = protocol
		cd.NodeRole = nodeRoles
		cd.Optional = false
		res = append(res, *cd)
	}

	return res, nil
}

func identifyContainerForPort(debugPod *debug.DebugPod, ssEntry string) (string, error) {
	pid, err := extractPID(ssEntry)
	if err != nil {
		return "", err
	}

	containerID, err := extractContainerID(debugPod, pid)
	if err != nil {
		return "", err
	}

	res, err := extractContainerInfo(debugPod, containerID)
	if err != nil {
		return "", err
	}

	return res, nil
}

func extractContainerInfo(debugPod *debug.DebugPod, containerID string) (string, error) {
	type ContainerInfo struct {
		Containers []struct {
			Labels struct {
				ContainerName string `json:"io.kubernetes.container.name"`
				PodName       string `json:"io.kubernetes.pod.name"`
				PodNamespace  string `json:"io.kubernetes.pod.namespace"`
			} `json:"labels"`
		} `json:"containers"`
	}
	containerInfo := &ContainerInfo{}
	cmd := fmt.Sprintf("crictl ps -o json --id %s", containerID)

	out, err := debugPod.ExecWithRetry(cmd, interval, duration)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(out, &containerInfo)
	if err != nil {
		return "", err
	}
	if len(containerInfo.Containers) != 1 {
		return "", fmt.Errorf("failed extracting pod info, got %d results expected 1. got output:\n%s", len(containerInfo.Containers), string(out))
	}

	containerName := containerInfo.Containers[0].Labels.ContainerName

	return containerName, nil
}

func extractContainerID(debugPod *debug.DebugPod, pid string) (string, error) {
	cmd := fmt.Sprintf("cat /proc/%s/cgroup", pid)
	out, err := debugPod.ExecWithRetry(cmd, interval, duration)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`crio-([0-9a-fA-F]+)\.scope`)

	match := re.FindStringSubmatch(string(out))

	if len(match) < 2 {
		return "", fmt.Errorf("container ID not found node:%s  pid: %s", debugPod.NodeName, pid)
	}

	containerID := match[1]
	return containerID, nil
}

func extractPID(input string) (string, error) {
	re := regexp.MustCompile(`pid=(\d+)`)

	match := re.FindStringSubmatch(input)

	if len(match) < 2 {
		return "", fmt.Errorf("PID not found in the input string")
	}

	pid := match[1]
	return pid, nil
}

func filterStrings(filterOutFn func(string) bool, strs []string) []string {
	res := make([]string, 0)
	for _, s := range strs {
		if filterOutFn(s) {
			continue
		}

		res = append(res, s)
	}

	return res
}

func parseComDetail(ssEntry string) (*types.ComDetails, error) {
	serviceName, err := extractServiceName(ssEntry)
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(ssEntry)
	portIdx := strings.LastIndex(fields[localAddrPortFieldIdx], ":")
	port := fields[localAddrPortFieldIdx][portIdx+1:]

	return &types.ComDetails{
		Direction: consts.IngressLabel,
		Port:      port,
		Service:   serviceName,
		Optional:  false}, nil
}

func extractServiceName(ssEntry string) (string, error) {
	re := regexp.MustCompile(`users:\(\("(?P<servicename>[^"]+)"`)

	match := re.FindStringSubmatch(ssEntry)

	if len(match) < 2 {
		return "", fmt.Errorf("service name not found in the input string: %s", ssEntry)
	}

	serviceName := match[re.SubexpIndex("servicename")]

	return serviceName, nil
}
