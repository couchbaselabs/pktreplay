package main

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/dustin/gomemcached"
	"github.com/dustin/gomemcached/client"
)

var wg = sync.WaitGroup{}
var todo int

const (
	ACTIVE  = uint32(1)
	REPLICA = uint32(2)
)

func responseReader(client *memcached.Client) {
	defer wg.Done()
	for ; todo > 0; todo-- {
		res := client.Receive()
		if res.Status != 0 {
			log.Printf("Read error: %v", res)
		}
	}
}

func setState(client *memcached.Client, vb int, to uint32) {
	extras := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(extras, to)
	req := gomemcached.MCRequest{
		Opcode:  gomemcached.CommandCode(0x3d),
		VBucket: uint16(vb),
		Key:     []byte{},
		Body:    []byte{},
		Extras:  extras,
	}
	client.Transmit(&req)
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Please supply a JSON file and server host:port")
	}
	filename, server := os.Args[1], os.Args[2]
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening file '%v': %v", filename, err)
	}

	data := map[string][]int{}
	err = json.NewDecoder(f).Decode(&data)
	if err != nil {
		log.Fatalf("Error reading JSON: %v", err)
	}

	client, err := memcached.Connect("tcp", server)
	if err != nil {
		log.Fatalf("Error connecting to %v: %v", server, err)
	}
	wg.Add(1)
	active_todo := len(data["SET"])
	replica_todo := len(data["TAP_MUTATION"])
	todo = active_todo + replica_todo
	go responseReader(client)

	for _, vb := range data["TAP_MUTATION"] {
		setState(client, vb, REPLICA)
		// log.Printf("Setting replica state for %v", vb)
	}

	for _, vb := range data["SET"] {
		setState(client, vb, ACTIVE)
		// log.Printf("Setting active state for %v", vb)
	}

	wg.Wait()
	log.Printf("Set %d active and %d replica vbuckets",
		active_todo, replica_todo)
}
