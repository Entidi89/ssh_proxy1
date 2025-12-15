package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/Entidi89/ssh_proxy1/internal/auth"
	"github.com/Entidi89/ssh_proxy1/internal/proxy"
	"github.com/Entidi89/ssh_proxy1/internal/rbac"
	"github.com/Entidi89/ssh_proxy1/internal/ws"
)

func main() {
	listenSSH := flag.String("ssh", "0.0.0.0:3023", "ssh listen")
	httpAddr := flag.String("http", "0.0.0.0:8080", "http/ws listen")
	hostKey := flag.String("host-key", "examples/host_key", "host private key")
	rbacFile := flag.String("rbac", "examples/rbac.json", "rbac json")
	recDir := flag.String("recdir", "sessions", "recorder dir")
	flag.Parse()

	// load host key
	kb, err := os.ReadFile(*hostKey)
	if err != nil {
		log.Fatalf("read host key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(kb)
	if err != nil {
		log.Fatalf("parse host key: %v", err)
	}

	// load rbac
	r, err := rbac.Load(*rbacFile)
	if err != nil {
		log.Fatalf("load rbac: %v", err)
	}

	agentMgr := ws.NewManager()
	proxySrv := proxy.NewProxyServer(agentMgr, r)

	// run HTTP (agent ws + admin UI) in goroutine
	go proxySrv.RunHTTP(*httpAddr)

	// start SSH server
	deps := proxy.SSHDependencies{
		AgentMgr:    agentMgr,
		RecorderDir: *recDir,
		RBAC:        r,
	}
	if err := proxy.StartSSHServer(*listenSSH, signer, deps); err != nil {
		log.Fatalf("ssh server exit: %v", err)
	}
	hostKey, _ := ssh.ParsePrivateKey([]byte(HOST_KEY))

	cfg := &ssh.ServerConfig{
		PasswordCallback: (&auth.PasswordAuth{
			Users: map[string]string{
				"alice|127.0.0.1:2222": "123456",
			},
		}).Callback,
	}
	cfg.AddHostKey(hostKey)

	go proxy.StartSSHServer(":3023", cfg)

	http.Handle("/", http.FileServer(http.Dir("web/playback")))
	http.ListenAndServe(":8080", nil)
}
