package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/ssh_proxy1/internal/ws"
	"github.com/ssh_proxy1/internal/rbac"
)

type ProxyServer struct {
	AgentMgr *ws.Manager
	RBAC     *rbac.RBAC
	Upgrader websocket.Upgrader
}

func NewProxyServer(agentMgr *ws.Manager, r *rbac.RBAC) *ProxyServer {
	return &ProxyServer{
		AgentMgr: agentMgr,
		RBAC:     r,
		Upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
	}
}

func (s *ProxyServer) RunHTTP(addr string) {
	http.HandleFunc("/ws", s.handleAgentWS)
	http.HandleFunc("/admin/rbac/reload", s.handleRBACReload)
	http.HandleFunc("/admin/rbac/list", s.handleRBACList)
	http.Handle("/web/playback/", http.StripPrefix("/web/playback/", http.FileServer(http.Dir("web/playback"))))
	log.Printf("proxy http listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func (s *ProxyServer) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "missing agent_id", http.StatusBadRequest)
		return
	}
	wsConn, err := s.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "upgrade failed", http.StatusInternalServerError)
		return
	}
	s.AgentMgr.RegisterAgent(agentID, wsConn)
	log.Printf("agent registered: %s", agentID)
}

func (s *ProxyServer) handleRBACReload(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "missing path", http.StatusBadRequest)
		return
	}
	if err := s.RBAC.Reload(path); err != nil {
		http.Error(w, fmt.Sprintf("reload failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("reloaded"))
}

func (s *ProxyServer) handleRBACList(w http.ResponseWriter, r *http.Request) {
	s.RBAC.mu.RLock()
	defer s.RBAC.mu.RUnlock()
	b, _ := json.Marshal(s.RBAC.Policies)
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}
