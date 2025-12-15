package recorder

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path"
	"sync"
	"time"
)

type Event struct {
	Ts   int64       `json:"ts"`
	Type string      `json:"type"` // meta,event,stdin,stdout,resize
	V    interface{} `json:"v"`
}

type SessionWriter struct {
	f   *os.File
	mu  sync.Mutex
	path string
}

func NewSessionWriter(dir, sessionID string, meta map[string]interface{}) (*SessionWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	p := path.Join(dir, "session-"+sessionID+".jsonl")
	f, err := os.Create(p)
	if err != nil {
		return nil, err
	}
	w := &SessionWriter{f: f, path: p}
	w.WriteEvent("meta", meta)
	w.WriteEvent("event", "session-start")
	return w, nil
}

func (w *SessionWriter) WriteEvent(typ string, v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	ev := Event{Ts: time.Now().UnixMilli(), Type: typ, V: v}
	b, _ := json.Marshal(ev)
	_, err := w.f.Write(append(b, '\n'))
	return err
}

func (w *SessionWriter) WriteBytes(typ string, b []byte) error {
	enc := base64.StdEncoding.EncodeToString(b)
	return w.WriteEvent(typ, enc)
}

func (w *SessionWriter) Close() error {
	w.WriteEvent("event", "session-end")
	return w.f.Close()
}

func (w *SessionWriter) Path() string { return w.path }
