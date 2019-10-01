package main

import (
	"encoding/json"
	"fmt"
	"github.com/eclipse/paho.mqtt.golang"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type FlowPacket struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol string
	Payload  string
}

func (pkt FlowPacket) GetTopic() string {
	return fmt.Sprintf("packet/%s/%s/%s/%s/%s", pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Protocol)
	//var sb strings.Builder
	//parts := []string{pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Protocol}
	//for idx, part := range parts {
	//	if part != "*" {
	//		sb.WriteString(part)
	//	} else {
	//		sb.WriteString("+")
	//	}
	//	if idx != len(parts)-1 {
	//		sb.WriteString("/")
	//	}
	//}
	//return sb.String()
}

// matches packets in a stream that match this
type WAVEFilter struct {
	SrcIPFilter    string
	DstIPFilter    string
	SrcPortFilter  string
	DstPortFilter  string
	ProtocolFilter string
}

// accepts filters like 10.10.0.1/24 and addresses
// and returns true if the filter matches the IP
func matchIPSubnet(filter, address string) bool {

	matchAddr := net.ParseIP(address)
	if matchAddr == nil {
		return false // invalid address
	}

	_parts := strings.Split(filter, "/")
	if len(_parts) != 2 {
		return filter == address || filter == "*"
	}
	maskLength, err := strconv.Atoi(_parts[1])
	if err != nil {
		return false // invalid filter
	}

	filterIP := net.ParseIP(_parts[0])
	if filterIP == nil {
		return false // invalid filter
	}
	if ip4 := filterIP.To4(); ip4 != nil {
		mask := net.CIDRMask(maskLength, 32)
		nwk := net.IPNet{IP: ip4, Mask: mask}
		return nwk.Contains(matchAddr)
	}
	if ip6 := filterIP.To16(); ip6 != nil {
		mask := net.CIDRMask(maskLength, 128)
		nwk := net.IPNet{IP: ip6, Mask: mask}
		return nwk.Contains(matchAddr)
	}

	return false
}

// returns true if the filter matches the given packet
// currently matches explicit IPs
func (filter *WAVEFilter) MatchesPacket(pkt FlowPacket) bool {
	// apply filter to src/dst IP
	if filter.SrcIPFilter != "" && !matchIPSubnet(filter.SrcIPFilter, pkt.SrcIP) {
		return false
	}
	if filter.DstIPFilter != "" && !matchIPSubnet(filter.DstIPFilter, pkt.DstIP) {
		return false
	}

	// filter on port
	if filter.SrcPortFilter != "" && filter.SrcPortFilter != "*" && filter.SrcPortFilter != pkt.SrcPort {
		return false
	}
	if filter.DstPortFilter != "" && filter.DstPortFilter != "*" && filter.DstPortFilter != pkt.DstPort {
		return false
	}

	// filter on protocol
	if filter.ProtocolFilter != "" && filter.ProtocolFilter != "*" && filter.ProtocolFilter != pkt.Protocol {
		return false
	}

	return true
}

func getClient(broker string) mqtt.Client {
	opts := mqtt.NewClientOptions().AddBroker(broker) //.SetClientID("gotrivial")
	opts.SetKeepAlive(2 * time.Second)
	opts.SetPingTimeout(1 * time.Second)
	c := mqtt.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}
	return c
}

func doScrape(c *cli.Context) error {
	client := getClient(c.String("broker"))

	defer util.Run()()
	if handle, err := pcap.OpenLive(c.String("interface"), 1600, true, pcap.BlockForever); err != nil {
		return err
	} else if err := handle.SetBPFFilter(c.String("filter")); err != nil { // optional
		return err
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
				continue
			}

			p := FlowPacket{}

			// decode network layer
			if net6, ok := packet.NetworkLayer().(*layers.IPv6); ok {
				flow := net6.NetworkFlow()
				p.SrcIP, p.DstIP = flow.Src().String(), flow.Dst().String()
			} else if net4, ok := packet.NetworkLayer().(*layers.IPv4); ok {
				flow := net4.NetworkFlow()
				p.SrcIP, p.DstIP = flow.Src().String(), flow.Dst().String()
			}

			// decode transport layer
			if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
				flow := tcp.TransportFlow()
				p.SrcPort, p.DstPort = flow.Src().String(), flow.Dst().String()
				p.Protocol = "tcp"
			} else if udp, ok := packet.TransportLayer().(*layers.UDP); ok {
				flow := udp.TransportFlow()
				p.SrcPort, p.DstPort = flow.Src().String(), flow.Dst().String()
				p.Protocol = "udp"
			}

			//TODO: add payload?
			log.Printf("%s: %+v", p.GetTopic(), p)
			pktjson, err := json.Marshal(p)
			if err != nil {
				log.Println("marshal packet", err)
				continue
			}

			token := client.Publish(p.GetTopic(), 0, false, pktjson)
			token.Wait()
		}
	}
	return nil
}

func doFilter(c *cli.Context) error {
	//client := getClient(c.String("broker"))
	log.Println(c.StringSlice("filter"))

	return nil
}

func main() {
	app := cli.NewApp()
	app.Commands = []cli.Command{
		{
			Name:  "scrape",
			Usage: "Scrape traffic off of an interface and push it onto MQTT",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "interface, i",
					Usage: "Interface to scrape packets from",
					Value: "eth0",
				},
				cli.StringFlag{
					Name:  "broker, b",
					Usage: "MQTT broker",
					Value: "tcp://localhost:1883",
				},
				cli.StringFlag{
					Name:  "filter, f",
					Usage: "BPF filter",
					Value: "ip",
				},
			},
			Action: doScrape,
		},
		{
			Name:   "filter",
			Usage:  "Filter traffic published on an MQTT bus according to a WAVE proof authenticated filter",
			Action: doFilter,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "broker, b",
					Usage: "MQTT broker",
					Value: "tcp://localhost:1883",
				},
				cli.StringSliceFlag{
					Name:  "filter, f",
					Usage: "Filters: srcip|dstip|srcport|dstport|transport",
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	//c := getClient(*broker)

	//f1 := WAVEFilter{
	//	SrcIPFilter: "192.168.1.1/16",
	//}
	//f2 := WAVEFilter{
	//	DstIPFilter: "192.168.1.1/16",
	//}

}
