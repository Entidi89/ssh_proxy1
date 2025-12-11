package main

import (
	"flag"
	"log"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/ssh_proxy1/internal/proxy"
	"github.com/ssh_proxy1/internal/ws"
	"github.com/ssh_proxy1/internal/rbac"
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
		AgentMgr: agentMgr,
		RecorderDir: *recDir,
		RBAC: r,
	}
	if err := proxy.StartSSHServer(*listenSSH, signer, deps); err != nil {
		log.Fatalf("ssh server exit: %v", err)
	}
}
