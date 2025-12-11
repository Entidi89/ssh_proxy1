package agent

import (
	"bytes"
	"encoding/json"
	"log"
	"net"

	"github.com/gorilla/websocket"
)

// incoming control format: {"type":"forward","id":"...","target":"127.0.0.1:22"}

func handleWSAgentConn(ws *websocket.Conn) {
	// central read loop
	sessionMap := map[string]net.Conn{}
	for {
		mt, msg, err := ws.ReadMessage()
		if err != nil {
			log.Printf("ws read err: %v", err)
			// cleanup
			for _, c := range sessionMap {
				c.Close()
			}
			return
		}
		if mt == websocket.TextMessage {
			var ctrl map[string]string
			if err := json.Unmarshal(msg, &ctrl); err != nil {
				continue
			}
			typ := ctrl["type"]
			id := ctrl["id"]
			switch typ {
			case "forward":
				target := ctrl["target"]
				// open local connection
				local, err := net.Dial("tcp", target)
				if err != nil {
					// send ack fail
					ack := map[string]string{"type": "forward-ack", "id": id, "status": "error", "error": err.Error()}
					_ = ws.WriteJSON(ack)
					continue
				}
				// store
				sessionMap[id] = local
				// send ack ok
				ack := map[string]string{"type": "forward-ack", "id": id, "status": "ok"}
				_ = ws.WriteJSON(ack)
				// start local->ws forward
				go func(id string, local net.Conn) {
					buf := make([]byte, 32*1024)
					for {
						n, err := local.Read(buf)
						if n > 0 {
							frame := append([]byte(id+"|"), buf[:n]...)
							_ = ws.WriteMessage(websocket.BinaryMessage, frame)
						}
						if err != nil {
							local.Close()
							// notify close
							_ = ws.WriteJSON(map[string]string{"type": "forward-close", "id": id})
							return
						}
					}
				}(id, local)
			case "close":
				if c, ok := sessionMap[id]; ok {
					c.Close()
					delete(sessionMap, id)
				}
			}
		} else if mt == websocket.BinaryMessage {
			// binary frame: sid|payload
			idx := bytes.IndexByte(msg, '|')
			if idx <= 0 {
				continue
			}
			sid := string(msg[:idx])
			payload := msg[idx+1:]
			if c, ok := sessionMap[sid]; ok {
				_, _ = c.Write(payload)
			}
		}
	}
}
