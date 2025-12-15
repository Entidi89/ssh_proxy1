package ws

import (
	"bytes"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// Protocol (text control JSON):
// proxy -> agent: {"type":"forward","id":"<sid>","target":"127.0.0.1:22"}
// proxy -> agent: {"type":"close","id":"<sid>"}
// agent -> proxy: {"type":"forward-ack","id":"<sid>","status":"ok"}
// Binary frames: prefix "<sid>|" then payload bytes

type AgentConn struct {
	ID         string
	Conn       *websocket.Conn
	sendMu     sync.Mutex
	sessions   sync.Map // map[string]chan []byte (recv from agent)
	recvActive chan struct{}
}

type Manager struct {
	mu       sync.Mutex
	agents   map[string]*AgentConn
	upgrader websocket.Upgrader
}

func NewManager() *Manager {
	return &Manager{
		agents:   map[string]*AgentConn{},
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
	}
}

func (m *Manager) RegisterAgent(id string, conn *websocket.Conn) *AgentConn {
	ac := &AgentConn{
		ID:         id,
		Conn:       conn,
		sessions:   sync.Map{},
		recvActive: make(chan struct{}),
	}
	m.mu.Lock()
	m.agents[id] = ac
	m.mu.Unlock()
	go ac.readLoop()
	return ac
}

func (a *AgentConn) readLoop() {
	for {
		mt, msg, err := a.Conn.ReadMessage()
		if err != nil {
			log.Printf("agent %s read err: %v", a.ID, err)
			a.closeAllSessions()
			return
		}
		if mt == websocket.TextMessage {
			// ignore for now or handle ack
			continue
		}
		if mt == websocket.BinaryMessage {
			// parse sid prefix
			idx := bytes.IndexByte(msg, '|')
			if idx <= 0 {
				continue
			}
			sid := string(msg[:idx])
			payload := msg[idx+1:]
			if chi, ok := a.sessions.Load(sid); ok {
				ch := chi.(chan []byte)
				// non-blocking push
				select {
				case ch <- payload:
				default:
				}
			}
		}
	}
}

func (a *AgentConn) closeAllSessions() {
	a.sessions.Range(func(k, v any) bool {
		sid := k.(string)
		ch := v.(chan []byte)
		close(ch)
		a.sessions.Delete(sid)
		return true
	})
}

func (m *Manager) GetAgent(id string) (*AgentConn, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	return a, ok
}

func (m *Manager) UnregisterAgent(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.agents, id)
}

func (a *AgentConn) SendControl(ctrl any) error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return a.Conn.WriteJSON(ctrl)
}

// Create session: returns 'recv' channel (agent->proxy) and 'send' channel proxy->agent
func (a *AgentConn) CreateSession(sid, target string) (recv <-chan []byte, send chan<- []byte, err error) {
	// create channels
	rch := make(chan []byte, 100)
	sch := make(chan []byte, 100)
	a.sessions.Store(sid, rch)

	// send forward control
	ctrl := map[string]string{"type": "forward", "id": sid, "target": target}
	if err := a.SendControl(ctrl); err != nil {
		a.sessions.Delete(sid)
		return nil, nil, err
	}

	// start goroutine to write from 'sch' to websocket as binary frames
	go func() {
		for chunk := range sch {
			frame := append([]byte(sid+"|"), chunk...)
			a.sendMu.Lock()
			_ = a.Conn.WriteMessage(websocket.BinaryMessage, frame)
			a.sendMu.Unlock()
		}
		// send close signal
		_ = a.SendControl(map[string]string{"type": "close", "id": sid})
	}()

	return rch, sch, nil
}

func (a *AgentConn) CloseSession(sid string) {
	if v, ok := a.sessions.Load(sid); ok {
		ch := v.(chan []byte)
		close(ch)
		a.sessions.Delete(sid)
	}
}
