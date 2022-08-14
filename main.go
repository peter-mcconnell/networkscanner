package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	timeout  = pcap.BlockForever
	devFound = false
	results  = make(map[string]int)
)

func main() {
	devPtr := flag.String("iface", "", "myInterfaceName")
	targetPtr := flag.String("target", "", "some target")
	flag.Parse()
	if *devPtr == "" {
		log.Panicln("you must pass an interface name, e.g. ./scanner -iface x")
	}

	devfound(*devPtr)

	if *targetPtr != "" {
		cap_filter := "tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18"
		cap_snaplen := int32(320)
		cap_promisc := false
		go capture(*devPtr, *targetPtr, cap_filter, cap_snaplen, cap_promisc)
		time.Sleep(1 * time.Second)
	}

	scan_filter := ""
	scan_snaplen := int32(1600)
	scan_promisc := true
	scan(*devPtr, scan_filter, scan_snaplen, scan_promisc)
}

func devfound(iface string) {
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
}

func capture(iface, target, filter string, snaplen int32, promisc bool) {
	if target == "" {
		log.Panicln(
			"you must pass a target, e.g. ./scanner -iface x -target 1.2.3.4",
		)
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
	fmt.Println("Capturing Packets")
	for packet := range source.Packets() {
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}
		srcHost := networkLayer.NetworkFlow().Src().String()
		srcPort := transportLayer.TransportFlow().Src().String()
		if srcHost != target {
			continue
		}
		results[srcPort] += 1
	}
}

func scan(iface, filter string, snaplen int32, promisc bool) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	fmt.Println("scanning ...")
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
