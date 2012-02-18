package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"text/tabwriter"

	"github.com/dustin/go-humanize"
	"github.com/dustin/gomemcached"
)

type reportMsg struct {
	final bool
	req   *gomemcached.MCRequest
	dnu   uint64
}

func has(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func report(ch <-chan reportMsg, wg *sync.WaitGroup) {
	counts := [256]uint64{}
	var dnu uint64
	vbuckets := map[string][]int{}
	for msg := range ch {
		if msg.req != nil {
			counts[int(msg.req.Opcode)]++
			vb := int(msg.req.VBucket)
			ops := msg.req.Opcode.String()
			if l, ok := vbuckets[ops]; ok {
				if !has(l, vb) {
					vbuckets[ops] = append(l, vb)
				}
			} else {
				vbuckets[ops] = []int{vb}
			}
		} else {
			dnu += msg.dnu
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

	if *dumpJson {
		log.Printf("Vbuckets in use:")
		err := json.NewEncoder(os.Stdout).Encode(vbuckets)
		if err != nil {
			log.Printf("Error in JSON encoding:  %v", err)
		}
	}

	log.Printf("Did not understand %s bytes", humanize.Bytes(dnu))

	wg.Done()
}
