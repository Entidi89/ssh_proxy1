package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Entidi89/ssh_proxy1/internal/connector"
	"github.com/Entidi89/ssh_proxy1/internal/recorder"
	"github.com/Entidi89/ssh_proxy1/internal/util"
	"github.com/Entidi89/ssh_proxy1/internal/rbac"
	"github.com/Entidi89/ssh_proxy1/internal/ws"
)

type SSHDependencies struct {
	AgentMgr    *ws.Manager
	RecorderDir string
	RBAC        *rbac.RBAC
}

func parseUser(raw string) (user, target string, err error) {
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid username format, expected user|host:port")
	}
	return parts[0], parts[1], nil
}

func StartSSHServer(listen string, hostKey ssh.Signer, deps SSHDependencies, authFn ssh.PasswordCallback) error {

	cfg := &ssh.ServerConfig{
		PasswordCallback: authFn,
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
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		go handleSession(newChan, sshConn, deps)
	}
}

func handleSession(newChan ssh.NewChannel, sshConn *ssh.ServerConn, deps SSHDependencies) {
	ch, _, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	user, target, err := parseUser(sshConn.User())
	if err != nil {
		ch.Write([]byte(err.Error() + "\n"))
		return
	}

	if deps.RBAC != nil && !deps.RBAC.Allows(user, target) {
		ch.Write([]byte("ACCESS DENIED\n"))
		return
	}

	var backend io.ReadWriteCloser

	if agent, ok := deps.AgentMgr.GetAgent(target); ok {
		sid := util.NewSessionID()
		recv, send, err := agent.CreateSession(sid, target)
		if err == nil {
			backend = connector.NewAgentConnAdapter(recv, send)
		}
	}

	if backend == nil {
		conn, err := connector.DirectDial(target)
		if err != nil {
			ch.Write([]byte(err.Error()))
			return
		}
		backend = conn
	}

	sessionID := util.NewSessionID()
	meta := map[string]interface{}{
		"user":   user,
		"target": target,
		"remote": sshConn.RemoteAddr().String(),
		"start":  time.Now().Format(time.RFC3339),
	}

	rec, _ := recorder.NewSessionWriter(deps.RecorderDir, sessionID, meta)
	defer rec.Close()

	done := make(chan struct{}, 2)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := backend.Read(buf)
			if n > 0 {
				ch.Write(buf[:n])
				rec.WriteBytes("stdout", buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				backend.Write(buf[:n])
				rec.WriteBytes("stdin", buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	<-done
	<-done

	if c, ok := backend.(interface{ Close() error }); ok {
		c.Close()
	}
}
