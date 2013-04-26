package main

import (
	"bufio"
	"io"
	"log"
	"time"
	"unicode"
	"unicode/utf8"

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

	if *verbose {
		log.Printf("%v", *req)
	}
	if client != nil {
		client.Transmit(req)
	}
	// log.Printf("from %v: %v", name, pkt)
	ch.reporter <- reportMsg{req: req}
}

type validator func(*gomemcached.MCRequest) bool

func allArePrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func saneKey(req *gomemcached.MCRequest) bool {
	return len(req.Key) >= 1 &&
		len(req.Key) < 250 &&
		utf8.Valid(req.Key) &&
		allArePrintable(string(req.Key))
}
func noBody(req *gomemcached.MCRequest) bool  { return len(req.Body) == 0 }
func hasBody(req *gomemcached.MCRequest) bool { return len(req.Body) > 0 }

var validators = map[gomemcached.CommandCode][]validator{
	gomemcached.GET:    {saneKey, noBody},
	gomemcached.GETQ:   {saneKey, noBody},
	gomemcached.DELETE: {saneKey, noBody},
	gomemcached.SET:    {saneKey, hasBody},
	gomemcached.SETQ:   {saneKey, hasBody},
}

func looksValid(req *gomemcached.MCRequest) bool {

	vs, ok := validators[req.Opcode]
	if !ok {
		return false
	}

	for _, v := range vs {
		if !v(req) {
			return false
		}
	}

	return true
}

func mcResponseConsumer(client *mc.Client) {
	defer childrenWG.Done()
	for {
		res, err := client.Receive()
		if err != nil {
			if err != io.EOF {
				log.Printf("Error in receive.  I think we're done: %v", err)
			}
			return
		}
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
				log.Printf("Invalid request found: op=%v, klen=%v, bodylen=%v",
					pkt.Opcode, len(pkt.Key), len(pkt.Body))
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
