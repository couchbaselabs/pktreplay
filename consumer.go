package main

import (
	"bufio"
	"io"
	"log"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/dustin/gomemcached"
	mc "github.com/dustin/gomemcached/client"
	"github.com/dustin/gomemcached/server"
)

type bytesource struct {
	ch       <-chan []byte
	reporter chan<- reportMsg
	current  []byte
}

func (b *bytesource) Read(out []byte) (int, error) {
	if len(b.current) == 0 {
		var ok bool
		b.current, ok = <-b.ch
		if !ok {
			return 0, io.EOF
		}
	}
	copied := copy(out, b.current)
	b.current = b.current[copied:]
	return copied, nil
}

func NewByteSource(from <-chan []byte, rchan chan<- reportMsg) *bytesource {
	return &bytesource{ch: from, reporter: rchan}
}

func readUntil(r *bufio.Reader, b byte) (skipped uint64, err error) {
	one := []byte{0}
	for {
		var bytes []byte
		bytes, err := r.Peek(1)
		if err != nil {
			return skipped, err
		}
		if len(bytes) == 1 && bytes[0] == b {
			return skipped, nil
		}
		n, err := r.Read(one)
		if err != nil {
			return skipped, err
		}
		skipped += uint64(n)
		if n == 1 && one[0] == b {
			return skipped, nil
		}
	}
	panic("Unreachable")
}

func processRequest(name string, ch *bytesource, req *gomemcached.MCRequest,
	client *mc.Client) {
	// log.Printf("Transmitting %v", *req)
	if client != nil {
		client.Transmit(req)
	}
	// log.Printf("from %v: %v", name, pkt)
	ch.reporter <- reportMsg{req: req}
}

func looksValid(req *gomemcached.MCRequest) bool {

	type validator func() bool

	requirements := make(map[gomemcached.CommandCode][]validator)

	saneKey := func() bool { return len(req.Key) >= 4 && len(req.Key) < 20 }
	noBody := func() bool { return len(req.Body) == 0 }
	hasBody := func() bool { return len(req.Body) > 0 }

	requirements[gomemcached.GET] = []validator{saneKey, noBody}
	requirements[gomemcached.GETQ] = []validator{saneKey, noBody}
	requirements[gomemcached.DELETE] = []validator{saneKey, noBody}
	requirements[gomemcached.SET] = []validator{saneKey, hasBody}
	requirements[gomemcached.SETQ] = []validator{saneKey, hasBody}

	if validators, ok := requirements[req.Opcode]; ok {
		for _, v := range validators {
			if !v() {
				return false
			}
		}
	}

	return true
}

func mcResponseConsumer(client *mc.Client) {
	defer childrenWG.Done()
	for {
		res := client.Receive()
		if res.Status != 0 {
			log.Printf("Memcached error:  %v", res)
		}
	}
}

func consumer(name string, ch *bytesource) {
	defer childrenWG.Done()

	var client *mc.Client
	if *server != "" {
		var err error
		client, err = mc.Connect("tcp", *server)
		if err == nil {
			defer client.Close()
			childrenWG.Add(1)
			go mcResponseConsumer(client)
		} else {
			log.Printf("Error connecting to memcached server: %v", err)
		}
	}

	msgs := 0
	rd := bufio.NewReader(ch)
	dnu := uint64(0)
	ever := true
	for ever {
		pkt, err := memcached.ReadPacket(rd)
		switch {
		case err == nil:
			if looksValid(&pkt) {
				processRequest(name, ch, &pkt, client)
			} else {
				log.Printf("Invalid request found: %v", pkt)
			}
			msgs++
		default:
			if *packetRecovery {
				skipped, err := readUntil(rd, gomemcached.REQ_MAGIC)
				dnu += skipped
				if err != nil {
					ever = false
					if err != io.EOF {
						log.Printf("Got an error seeking truth: %v", err)
					}
				}
			} else {
				ever = false
			}
		case err == io.EOF:
			ever = false
		}
	}
	// Just read the thing to completion.
	for bytes := range ch.ch {
		dnu += uint64(len(bytes))
	}
	log.Printf("Processed %d messages, skipped %s from %s",
		msgs, humanize.Bytes(dnu), name)
	ch.reporter <- reportMsg{final: true, dnu: dnu}
}

func timeOffset(pktTime, firstPacket, localStart time.Time) time.Duration {
	now := time.Now()
	pktElapsed := pktTime.Sub(firstPacket)
	localElapsed := time.Duration(float64(now.Sub(localStart)) * *timeScale)

	return time.Duration(float64(pktElapsed-localElapsed) / *timeScale)

}
