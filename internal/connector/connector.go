package connector

import (
	"io"
	"net"
)

// DirectDial TCP
func DirectDial(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

// AgentAdapter wraps ws.AgentConn session channels to io.ReadWriteCloser
type AgentConnAdapter struct {
	recv <-chan []byte
	send chan<- []byte
	closed chan struct{}
}

func NewAgentConnAdapter(recv <-chan []byte, send chan<- []byte) *AgentConnAdapter {
	return &AgentConnAdapter{recv: recv, send: send, closed: make(chan struct{})}
}

func (a *AgentConnAdapter) Read(b []byte) (int, error) {
	select {
	case data, ok := <-a.recv:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		return n, nil
	}
}

func (a *AgentConnAdapter) Write(b []byte) (int, error) {
	select {
	case a.send <- b:
		return len(b), nil
	case <-a.closed:
		return 0, io.ErrClosedPipe
	}
}

func (a *AgentConnAdapter) Close() error {
	close(a.closed)
	return nil
}
