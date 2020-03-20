package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/abrampers/inkle/intercept"
)

var (
	device      = flag.String("device", "lo0", "Network device to sniff on")
	snaplen     = flag.Int("snaplen", 1024, "The maximum size to read for each packet")
	promiscuous = flag.Bool("prom", false, "Whether to put the interface in promiscuous mode")
	timeout     = flag.Duration("timeout", 300*time.Millisecond, "Timeout in nanosecond")
)

func main() {
	flag.Parse()

	interceptor := intercept.NewPacketInterceptor(*device, int32(*snaplen), *promiscuous, *timeout)

	for packet := range interceptor.Packets() {
		if packet.IsIPv4 {
			fmt.Println("IPv4 SrcIP:        ", packet.IPv4.SrcIP)
			fmt.Println("IPv4 DstIP:        ", packet.IPv4.DstIP)
		} else {
			fmt.Println("IPv6 SrcIP:        ", packet.IPv6.SrcIP)
			fmt.Println("IPv6 DstIP:        ", packet.IPv6.DstIP)
		}
		fmt.Println("TCP srcPort:       ", packet.TCP.SrcPort)
		fmt.Println("TCP dstPort:       ", packet.TCP.DstPort)
		fmt.Println("HTTP/2:            ", packet.HTTP2.Frame)
	}
}
