package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	snaplen  = int32(1600)
	promisc  = true
	timeout  = pcap.BlockForever
	filter   = ""
	devFound = false
)

func main() {
	devPtr := flag.String("iface", "", "myInterfaceName")
	flag.Parse()
	if *devPtr == "" {
		log.Panicln("you must pass an interface name, e.g. ./scanner -iface x")
	}
	scan(*devPtr)
}

func scan(iface string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln(err)
	}

	for _, device := range devices {
		if device.Name == iface {
			devFound = true
			break
		}
	}
	if !devFound {
		log.Panicf("device %s not found!", iface)
	}

	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		log.Panicln(err)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(filter); err != nil {
		log.Panicln(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		fmt.Println(packet)
	}
}
