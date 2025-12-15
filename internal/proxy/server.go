package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/Entidi89/ssh_proxy1/internal/rbac"
	"github.com/Entidi89/ssh_proxy1/internal/recorder"
	"github.com/Entidi89/ssh_proxy1/internal/ws"
	"github.com/ssh_proxy1/internal/util"
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
	policies := s.RBAC.ListPolicies()
	b, _ := json.Marshal(policies)
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func StartSSHServer(addr string, cfg *ssh.ServerConfig) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Println("SSH proxy listening on", addr)

	for {
		conn, _ := ln.Accept()
		go handle(conn, cfg)
	}
}

func handle(raw net.Conn, cfg *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		go handleSession(ch, sshConn)
	}
}

func handleSession(nc ssh.NewChannel, conn *ssh.ServerConn) {
	ch, _, _ := nc.Accept()
	defer ch.Close()

	// user|host:port
	parts := strings.Split(conn.User(), "|")
	if len(parts) != 2 {
		ch.Write([]byte("invalid username format\n"))
		return
	}

	user := parts[0]
	target := parts[1]

	backend, err := net.Dial("tcp", target)
	if err != nil {
		ch.Write([]byte(err.Error()))
		return
	}
	defer backend.Close()

	sid := util.NewSessionID()
	rec, _ := recorder.NewWriter("recordings", sid, user, target)
	defer rec.Close()

	done := make(chan bool, 2)

	go pipe(backend, ch, rec, "stdout", done)
	go pipe(ch, backend, rec, "stdin", done)

	<-done
	<-done
}

func pipe(src io.Reader, dst io.Writer, rec *recorder.Writer, dir string, done chan bool) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
			rec.Write(dir, buf[:n])
		}
		if err != nil {
			break
		}
	}
	done <- true
}
