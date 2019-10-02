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

var mqtt1 = Filter{
	SrcPort: "1883",
}
var mqtt2 = Filter{
	DstPort: "1883",
}

func isMQTTPacket(pkt FlowPacket) bool {
	return mqtt1.MatchesPacket(pkt) || mqtt2.MatchesPacket(pkt)
}

type FlowPacket struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol string
	Payload  string
}

func (pkt FlowPacket) ToJSON() []byte {
	b, err := json.Marshal(pkt)
	if err != nil {
		panic(err)
	}
	return b
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
type Filter struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol string
	// topic to push filtered packets onto
	Topic string
}

func (f Filter) ToJSON() []byte {
	b, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	return b
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
func (filter *Filter) MatchesPacket(pkt FlowPacket) bool {
	// apply filter to src/dst IP
	if filter.SrcIP != "" && !matchIPSubnet(filter.SrcIP, pkt.SrcIP) {
		return false
	}
	if filter.DstIP != "" && !matchIPSubnet(filter.DstIP, pkt.DstIP) {
		return false
	}

	// filter on port
	if filter.SrcPort != "" && filter.SrcPort != "*" && filter.SrcPort != pkt.SrcPort {
		return false
	}
	if filter.DstPort != "" && filter.DstPort != "*" && filter.DstPort != pkt.DstPort {
		return false
	}

	// filter on protocol
	if filter.Protocol != "" && filter.Protocol != "*" && filter.Protocol != pkt.Protocol {
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

			// filter out MQTT
			if isMQTTPacket(p) {
				continue
			}

			//TODO: add payload?
			log.Printf("%s: %+v", p.GetTopic(), p)

			token := client.Publish(p.GetTopic(), 0, false, p.ToJSON())
			token.Wait()
		}
	}
	return nil
}

func makeFilter(f Filter) func(mqtt.Client, mqtt.Message) {

	return func(client mqtt.Client, msg mqtt.Message) {
		var pkt FlowPacket
		err := json.Unmarshal(msg.Payload(), &pkt)
		if err != nil {
			log.Println("Could not load packet")
		}

		if f.MatchesPacket(pkt) {
			// publish
			token := client.Publish(f.Topic, 0, false, msg.Payload())
			token.Wait()
		}
	}
}

func doFilter(c *cli.Context) error {
	client := getClient(c.String("broker"))

	filter_cb := func(client mqtt.Client, msg mqtt.Message) {
		var filter Filter
		err := json.Unmarshal(msg.Payload(), &filter)
		if err != nil {
			log.Println("Could not load packet")
		}
		if filter.Topic == "" {
			log.Println("Filter needs output topic")
			return
		}
		log.Println("Making filter", filter)
		cb := makeFilter(filter)

		// subscribe to the broker to get all packets
		token := client.Subscribe("packet/#", 1, cb)
		token.Wait()

	}

	// subscribe to topic that creates filters
	token1 := client.Subscribe("make_filter", 1, filter_cb)
	token1.Wait()
	defaultFilter := Filter{
		Protocol: "tcp",
		Topic:    "gabetest",
	}
	client.Publish("make_filter", 1, false, defaultFilter.ToJSON())

	select {}

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
			Name:   "netview",
			Usage:  "Filter traffic published on an MQTT bus according to a WAVE proof authenticated filter",
			Action: doFilter,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "broker, b",
					Usage: "MQTT broker",
					Value: "tcp://localhost:1883",
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	//c := getClient(*broker)

	//f1 := Filter{
	//	SrcIPFilter: "192.168.1.1/16",
	//}
	//f2 := Filter{
	//	DstIPFilter: "192.168.1.1/16",
	//}

}
