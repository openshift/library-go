package library

import "net"

// FreeLocalTCPPort returns a local TCP port which is very likely to be unused.
func FreeLocalTCPPort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
