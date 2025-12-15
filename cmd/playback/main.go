package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

type Event struct {
	Ts   int64       `json:"ts"`
	Type string      `json:"type"`
	V    interface{} `json:"v"`
}

func main() {
	fpath := flag.String("file", "", "session jsonl file")
	flag.Parse()
	if *fpath == "" {
		fmt.Println("usage: playback -file session-<id>.jsonl")
		return
	}
	f, err := os.Open(*fpath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var start int64 = -1
	var last int64 = 0
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.Type != "stdout" && e.Type != "event" {
			continue
		}
		if start == -1 {
			start = e.Ts
			last = start
		}
		delta := time.Duration(e.Ts-last) * time.Millisecond
		if delta > 0 {
			time.Sleep(delta)
		}
		if e.Type == "stdout" {
			s, _ := e.V.(string)
			b, _ := base64.StdEncoding.DecodeString(s)
			os.Stdout.Write(b)
		}
		last = e.Ts
	}
	fmt.Println("\n-- playback end --")
}
