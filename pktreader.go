package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/dustin/gomemcached"
	"github.com/dustin/gomemcached/server"
	"github.com/dustin/gopcap"
)

var timeScale *float64 = flag.Float64("timescale", 1.0,
	"The device that speeds up and slows down time")

const channelSize = 10000

var childrenWG = sync.WaitGroup{}

type reportMsg struct {
	final bool
	op    gomemcached.CommandCode
	dnu   uint64
}

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

func processRequest(name string, ch *bytesource, req *gomemcached.MCRequest) {
	// fmt.Printf("from %v: %v\n", name, pkt)
	ch.reporter <- reportMsg{op: req.Opcode}
}

func consumer(name string, ch *bytesource) {
	defer childrenWG.Done()
	msgs := 0
	rd := bufio.NewReader(ch)
	dnu := uint64(0)
	ever := true
	for ever {
		pkt, err := memcached.ReadPacket(rd)
		switch {
		case err == nil:
			switch pkt.Opcode {
			case gomemcached.GET, gomemcached.SET, gomemcached.GETQ,
				gomemcached.SETQ, gomemcached.DELETE:
				if len(pkt.Key) > 16 || len(pkt.Key) < 4 {
					fmt.Printf("Weird invalid looking packet: %v\n", pkt)
				} else {
					processRequest(name, ch, &pkt)
				}
			default:
				// not weird, invalid looking request
				processRequest(name, ch, &pkt)
			}
			msgs++
		default:
			// fmt.Printf("recovering from error:  %v\n", err)
			skipped, err := readUntil(rd, gomemcached.REQ_MAGIC)
			dnu += skipped
			if err != nil {
				ever = false
				if err != io.EOF {
					fmt.Printf("Got an error seeking truth: %v", err)
				}
			}
		case err == io.EOF:
			ever = false
		}
	}
	// Just read the thing to completion.
	for bytes := range ch.ch {
		dnu += uint64(len(bytes))
	}
	fmt.Printf("Completed %d messages, did not understand %s from %s\n",
		msgs, humanize.Bytes(dnu), name)
	ch.reporter <- reportMsg{final: true, dnu: dnu}
}

func syncTime(pktTime, firstPacket, localStart time.Time) {
	now := time.Now()
	pktElapsed := pktTime.Sub(firstPacket)
	localElapsed := time.Duration(float64(now.Sub(localStart)) * *timeScale)

	toSleep := time.Duration(float64(pktElapsed-localElapsed) / *timeScale)
	if toSleep > 0 {
		time.Sleep(toSleep)
	}
}

func stream(filename string, rchan chan<- reportMsg) {
	h, err := pcap.Openoffline(filename)
	if h == nil {
		fmt.Printf("Openoffline(%s) failed: %s\n", filename, err)
		return
	}
	defer h.Close()

	clients := make(map[string]chan []byte)
	servers := make(map[string]bool)

	pkt := h.Next()
	if pkt == nil {
		fmt.Printf("No packets.")
		return
	}
	started := time.Now()
	first := pkt.Time.Time()

	for ; pkt != nil; pkt = h.Next() {
		pkt.Decode()
		tcp, ip := pkt.TCP, pkt.IP
		if tcp != nil {
			isAck := tcp.Flags&pcap.TCP_ACK != 0
			sender := fmt.Sprintf("%s:%d", ip.SrcAddr(), tcp.SrcPort)
			isServer := servers[sender]
			if tcp.Flags&pcap.TCP_SYN != 0 && isAck {
				servers[sender] = true
				isServer = true
			}

			if !isServer {
				ch := clients[sender]
				if ch == nil {
					ch = make(chan []byte, channelSize)
					childrenWG.Add(1)
					go consumer(sender, NewByteSource(ch, rchan))
					clients[sender] = ch
					// fmt.Printf("Inferred connect from " + sender + "\n")
				}
				if len(pkt.Payload) > 0 {
					ch <- pkt.Payload
				}
				if tcp.Flags&(pcap.TCP_SYN|pcap.TCP_RST) != 0 && !isAck {
					close(clients[sender])
					delete(clients, sender)
					// fmt.Printf("Disconnect from " + sender + "\n")
				}
			}
		}
		t := pkt.Time.Time()
		syncTime(t, first, started)
	}
	for _, ch := range clients {
		close(ch)
	}
}

func report(ch <-chan reportMsg, wg *sync.WaitGroup) {
	counts := [256]uint64{}
	var dnu uint64
	for msg := range ch {
		if msg.final {
			dnu += msg.dnu
		} else {
			counts[int(msg.op)]++
		}
	}

	tw := tabwriter.NewWriter(os.Stdout, 8, 4, 2, ' ', 0)
	for id, count := range counts {
		if count > 0 {
			cmd := gomemcached.CommandCode(id).String()
			fmt.Fprintf(tw, "%s\t%d\n", cmd, count)
		}
	}
	tw.Flush()

	fmt.Printf("Did not understand %s bytes\n", humanize.Bytes(dnu))

	wg.Done()
}

func main() {
	flag.Parse()
	reportchan := make(chan reportMsg, 100000)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go report(reportchan, &wg)
	stream(flag.Arg(0), reportchan)
	childrenWG.Wait()
	close(reportchan)
	wg.Wait()
}
