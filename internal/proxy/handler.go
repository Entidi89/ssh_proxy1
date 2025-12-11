package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ssh_proxy1/internal/connector"
	"github.com/ssh_proxy1/internal/recorder"
	"github.com/ssh_proxy1/internal/util"
)

type SSHDependencies struct {
	AgentMgr *ws.Manager
	RecorderDir string
	RBAC *rbac.RBAC
	// SecretFetcher interface could be added here to integrate with Vault
}

func StartSSHServer(listen string, hostKey ssh.Signer, deps SSHDependencies) error {
	cfg := &ssh.ServerConfig{
		NoClientAuth: true, // For prototype: you should implement proper auth
	}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("SSH proxy listening on %s", listen)
	for {
		raw, err := ln.Accept()
		if err != nil {
			log.Printf("accept err: %v", err)
			continue
		}
		go handleConn(raw, cfg, deps)
	}
}

func handleConn(raw net.Conn, cfg *ssh.ServerConfig, deps SSHDependencies) {
	sshConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		log.Printf("ssh handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("client connected %s user=%s", sshConn.RemoteAddr(), sshConn.User())
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			go handleSession(newChan, sshConn, deps)
		default:
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func handleSession(newChan ssh.NewChannel, sshConn *ssh.ServerConn, deps SSHDependencies) {
	ch, _, err := newChan.Accept()
	if err != nil {
		log.Printf("accept session err: %v", err)
		return
	}
	defer ch.Close()

	// username expected format: "alice|target:port" for prototype
	userRaw := sshConn.User()
	parts := strings.SplitN(userRaw, "|", 2)
	var user, target string
	if len(parts) == 2 {
		user = parts[0]
		target = parts[1]
	} else {
		// fallback: reject
		ch.Write([]byte("invalid username format, expected user|host:port\n"))
		return
	}

	// RBAC enforce
	if deps.RBAC != nil && !deps.RBAC.Allows(user, target) {
		ch.Write([]byte("ACCESS DENIED\n"))
		return
	}

	// Decide agent or direct
	// AgentMgr expects agent_id same as host (in prototype), adapt as needed.
	agentID := target // mapping convention
	var backend io.ReadWriteCloser
	if agentConn, ok := deps.AgentMgr.GetAgent(agentID); ok && agentConn != nil {
		// create session
		sid := util.NewSessionID()
		recv, send, err := agentConn.CreateSession(sid, target)
		if err == nil {
			// wrap to adapter
			backend = connector.NewAgentConnAdapter(recv, send)
			// Ensure backend implements ReadWriteCloser
			// (our adapter lacks Close; we can keep it simple and set to nil safe)
		}
	}

	if backend == nil {
		// direct dial
		conn, err := connector.DirectDial(target)
		if err != nil {
			ch.Write([]byte(fmt.Sprintf("cannot connect to target: %v\n", err)))
			return
		}
		backend = conn
	}

	// recorder
	sessionID := util.NewSessionID()
	meta := map[string]interface{}{
		"user": user,
		"target": target,
		"remote": sshConn.RemoteAddr().String(),
		"start": time.Now().Format(time.RFC3339),
	}
	rec, _ := recorder.NewSessionWriter(deps.RecorderDir, sessionID, meta)
	defer func() {
		if rec != nil { rec.Close() }
	}()

	// proxy loops
	done := make(chan struct{}, 2)

	// backend -> client
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := backend.Read(buf)
			if n > 0 {
				_, _ = ch.Write(buf[:n])
				if rec != nil { rec.WriteBytes("stdout", buf[:n]) }
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	// client -> backend
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				_, _ = backend.Write(buf[:n])
				if rec != nil { rec.WriteBytes("stdin", buf[:n]) }
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
	<-done

	// close backend if possible
	if c, ok := backend.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}
