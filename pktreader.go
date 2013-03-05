package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/dustin/gomemcached/server"
	"github.com/dustin/gopcap"
	"github.com/dustin/replaykit"
)

var timeScale = flag.Float64("timescale", 1.0,
	"The device that speeds up and slows down time")
var packetRecovery = flag.Bool("recover", true,
	"Attempt to recover from corrupt memcached streams")
var dumpJson = flag.Bool("dumpjson", false,
	"Dump op -> vbucket map discovered in trace")
var maxBodyLen = flag.Uint("maxBodyLen", uint(memcached.MaxBodyLen),
	"Maximum body length of a valid packet")
var server = flag.String("server", "localhost:11211",
	"memcached server to connect to")
var verbose = flag.Bool("v", false, "print out all the things")

const channelSize = 10000

var childrenWG = sync.WaitGroup{}

type packetEvent struct {
	pc *pcap.Packet
}

type pktSrc struct {
	p *pcap.Pcap
}

func (pe packetEvent) TS() time.Time {
	return pe.pc.Time.Time()
}

func (p *pktSrc) Next() replay.Event {
	n := p.p.Next()
	if n == nil {
		return nil
	}
	return packetEvent{n}
}

// Returns how far off schedule we were
func stream(filename string, rchan chan<- reportMsg) time.Duration {
	h, err := pcap.Openoffline(filename)
	if h == nil {
		log.Fatalf("Openoffline(%s) failed: %s", filename, err)
	}
	defer h.Close()

	clients := make(map[string]chan []byte)
	servers := make(map[string]bool)

	defer func() {
		for _, ch := range clients {
			close(ch)
		}
	}()

	psrc := &pktSrc{h}

	r := replay.New(*timeScale)

	return r.Run(psrc, replay.FunctionAction(func(ev replay.Event) {
		pkt := ev.(packetEvent).pc
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
					// log.Printf("Inferred connect from " + sender)
				}
				if len(pkt.Payload) > 0 {
					ch <- pkt.Payload
				}
				if tcp.Flags&(pcap.TCP_SYN|pcap.TCP_RST) != 0 && !isAck {
					close(clients[sender])
					delete(clients, sender)
					// log.Printf("Disconnect from " + sender)
				}
			}
		}
	}))
}

func main() {
	log.SetFlags(log.Lmicroseconds)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [params] file.pcap\n",
			os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "ERROR:  Must supply a pcap file.\n")
		flag.Usage()
		os.Exit(1)
	}
	memcached.MaxBodyLen = uint32(*maxBodyLen)
	reportchan := make(chan reportMsg, 100000)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go report(reportchan, &wg)
	toff := stream(flag.Arg(0), reportchan)
	childrenWG.Wait()
	close(reportchan)
	wg.Wait()
	tlbl := "early"
	if int64(toff) < 0 {
		tlbl = "late"
		toff = 0 - toff
	}
	log.Printf("Finished %v %s.", toff, tlbl)

}
