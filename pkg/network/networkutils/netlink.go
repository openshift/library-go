// +build linux

package networkutils

import (
	"fmt"
	"k8s.io/apimachinery/pkg/util/sets"

	nl "github.com/elastic/gosigar/sys/linux"
)

// SocketDiagMsg struct that holds data returned from netlink and filtered for our purposes
//
// full description can be found at https://man7.org/linux/man-pages/man7/sock_diag.7.html
// the original struct name is inet_diag_msg
type SocketDiagMsg struct {
	// state holds a human-readable value of the socket state, like ESTABLISHED or LISTEN
	state string

	// recvQ - from https://man7.org/linux/man-pages/man7/sock_diag.7.html:
	//  for listening sockets: the number of pending connections.
	//  for other sockets: the amount of data in the incoming queue.
	//
	// in practice it tells you the number of bytes of data that have been received by the kernel but haven't been copied by the process
	recvQ int

	// sendQ - from https://man7.org/linux/man-pages/man7/sock_diag.7.html:
	//  for listening sockets: the backlog length.
	//  for other sockets: the amount of memory available for sending.
	//
	// in practice it tells you the number of bytes data that have been sent but hasn't been acknowledged
	sendQ int

	// localAddress holds an IP address and the port of the local process
	localAddress string

	// remoteAddress holds an IP address and the port of the remote process
	remoteAddress string

	// timer - see timerFieldToHumanReadable for possible values
	timer string

	// retransmissions - for timer values 1, 2, and 4, this field contains
	// the number of retransmits. For other timer values, this field is set to 0.
	retransmissions int

	// timerExpiry - for TCP sockets that have an active timer, this field
	// describes its expiration time in milliseconds.  For other sockets, this field is set to 0.
	//
	// note: it will hold the current value at the probe time
	timerExpiry int
}

// for TCP sockets, this field describes the type of timer
// that is currently active for the socket.  It is set to one of the following constants:
//
// 0 - no timer is active
// 1 - a retransmit timer
// 2 - a keep-alive timer
// 3 - a TIME_WAIT timer
// 4 - a zero window probe timer
func timerFieldToHumanReadable(timer uint8) string {
	switch timer {
	case 0:
		return "no-timer"
	case 1:
		return "retransmit"
	case 2:
		return "keep-alive"
	case 3:
		return "time-wait"
	case 4:
		return "probe"
	default:
		return "unknown"
	}
}

// GetNetworkSocketsDiagnosticMsg returns an array of SocketDiagMsg both for IPv4 and IPv6 sockets.
// Check SocketDiagMsg struct to see what data it holds.
//
// This method uses netlink subsystem for obtaining information
// about sockets of various address families from the linux kernel.
//
// in the future we could:
//  use InetDiagReqV2 to specify an address family (IPv4 or IPv6) and a protocol (TCP, UDP)
//  ask the kernel to only return sockets for specific port or address (filtering)
//
// Note:
//  depending on the platform this function is run on, it might require setting custom permissions.
func GetNetworkSocketsDiagnosticMsg() ([]*SocketDiagMsg, error) {
	rawInetDiagRsp, err := nl.NetlinkInetDiagWithBuf(nl.NewInetDiagReq(), nil, nil)
	if err != nil {
		return nil, err
	}

	ret := make([]*SocketDiagMsg, 0, len(rawInetDiagRsp))
	for _, rawDiagMsg := range rawInetDiagRsp {
		ret = append(ret, &SocketDiagMsg{
			state:           nl.TCPState(rawDiagMsg.State).String(),
			recvQ:           int(rawDiagMsg.RQueue),
			sendQ:           int(rawDiagMsg.WQueue),
			localAddress:    fmt.Sprintf("%v:%v", rawDiagMsg.SrcIP().String(), rawDiagMsg.SrcPort()),
			remoteAddress:   fmt.Sprintf("%v:%v", rawDiagMsg.DstIP().String(), rawDiagMsg.DstPort()),
			timer:           timerFieldToHumanReadable(rawDiagMsg.Timer),
			retransmissions: int(rawDiagMsg.Retrans),
			timerExpiry:     int(rawDiagMsg.Expires / 1000),
		})
	}

	return ret, nil
}

// GetSocketStateChanges returns a list of SocketDiagMsg that has changed according the current state and data returned from GetNetworkSocketsDiagnosticMsg method
func GetSocketStateChanges(socketsDiag []*SocketDiagMsg, state map[string]*SocketDiagMsg) []*SocketDiagMsg {
	ret := []*SocketDiagMsg{}
	visitedSocketKeys := sets.String{}
	changedSocketsKeys := sets.String{}
	for _, currentSocketDiag := range socketsDiag {
		socketKey := currentSocketDiag.localAddress
		if changed := detectSocketChangesAndUpdate(socketKey, currentSocketDiag, state); changed {
			changedSocketsKeys.Insert(socketKey)
			ret = append(ret, currentSocketDiag)
		}
		visitedSocketKeys.Insert(socketKey)
	}

	// detect closed sockets
	allSocketKeys := sets.String{}
	for socketKey := range state {
		allSocketKeys.Insert(socketKey)
	}
	closedSocketKeys := allSocketKeys.Difference(visitedSocketKeys).List()
	for _, closedSocketKey := range closedSocketKeys {
		prevSocketDiag, _ := state[closedSocketKey]
		prevSocketDiag.state = "CLOSED"
		ret = append(ret, prevSocketDiag)
		delete(state, closedSocketKey)
	}
	return ret
}

// detectSocketChangesAndUpdate detect changes to the currentSocketDiag and updates the state.
// It notifies the caller whether the currentSocketDiag has changed so that further processing can be done.
func detectSocketChangesAndUpdate(socketKey string, currentSocketDiag *SocketDiagMsg, state map[string]*SocketDiagMsg) bool {
	// store the copy
	currentSocketDiagCpy := *currentSocketDiag

	// clear fields that are not stable and we don't want to track
	currentSocketDiagCpy.timerExpiry = 0

	// new socket that hasn't been seen
	prevSocketDiag, exists := state[socketKey]
	if !exists {
		state[socketKey] = &currentSocketDiagCpy
		return true
	}

	// SocketDiagMsg holds simple types thus dereferencing and comparing works
	if *prevSocketDiag == currentSocketDiagCpy {
		return false
	}

	// something has changed
	state[socketKey] = &currentSocketDiagCpy
	return true
}
