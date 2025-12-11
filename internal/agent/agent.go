package agent

import (
	"log"
	"time"

	"github.com/gorilla/websocket"
)

type AgentConfig struct {
	ProxyWS string // e.g. ws://proxy-host:8080/ws?agent_id=ID
}

func RunAgent(cfg AgentConfig) error {
	u := cfg.ProxyWS
	for {
		log.Printf("connecting to %s", u)
		d := websocket.DefaultDialer
		ws, _, err := d.Dial(u, nil)
		if err != nil {
			log.Printf("ws dial err: %v; retry in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("connected to proxy ws")
		handleWSAgentConn(ws)
		// on return, connection closed; reconnect
		log.Printf("reconnect in 3s")
		time.Sleep(3 * time.Second)
	}
}
