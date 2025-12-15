package main

import (
	"flag"
	"log"

	"github.com/Entidi89/ssh_proxy1/internal/agent"
)

func main() {
	proxyWS := flag.String("proxy-ws", "ws://localhost:8080/ws?agent_id=127.0.0.1:2222", "proxy websocket URL with agent_id queryparam")
	flag.Parse()

	cfg := agent.AgentConfig{ProxyWS: *proxyWS}
	if err := agent.RunAgent(cfg); err != nil {
		log.Fatalf("agent error: %v", err)
	}
}
