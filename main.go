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
	"os"
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

	var handle *pcap.Handle
	var handleerr error
	if _, err := os.Stat(c.String("interface")); os.IsNotExist(err) {
		handle, handleerr = pcap.OpenLive(c.String("interface"), 1600, true, pcap.BlockForever)
	} else if err == nil {
		handle, handleerr = pcap.OpenOffline("/tmp/pcap")
	}
	if handleerr != nil {
		return handleerr
	}

	//if handle, err := pcap.OpenOffline("/tmp/pcap"); err != nil {
	//if handle, err := pcap.OpenLive(c.String("interface"), 1600, true, pcap.BlockForever); err != nil {
	//if handle, err := pcap.OpenLive(c.String("interface"), 1600, true, pcap.BlockForever); err != nil {
	//return err
	if err := handle.SetBPFFilter(c.String("filter")); err != nil { // optional
		return err
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			packet, err := packetSource.NextPacket()
			if err != nil && err == pcap.NextErrorNoMorePackets {
				log.Println("no more packets; waiting")
				time.Sleep(1 * time.Second)
				continue
			} else if err != nil {
				log.Println("packet source", err)
				continue
			}

			//for packet := range packetSource.Packets() {
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

			if m, ok := packet.LinkLayer().(*layers.Ethernet); ok {
				flow := m.LinkFlow()
				p.SrcMAC, p.DstMAC = flow.Src().String(), flow.Dst().String()
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

func makeFilter(fb FilterBundle) func(mqtt.Client, mqtt.Message) {
	return func(client mqtt.Client, msg mqtt.Message) {
		var pkt FlowPacket
		err := json.Unmarshal(msg.Payload(), &pkt)
		if err != nil {
			log.Println("Could not load packet")
		}

		if fb.MatchesPacket(pkt) {
			// publish
			token := client.Publish(fb.Topic, 0, false, msg.Payload())
			token.Wait()
		}
	}
}

func doFilter(c *cli.Context) error {
	client := getClient(c.String("broker"))

	filter_cb := func(client mqtt.Client, msg mqtt.Message) {
		var fb FilterBundle
		err := json.Unmarshal(msg.Payload(), &fb)
		if err != nil {
			log.Println("Could not load packet")
		}
		if fb.Topic == "" {
			log.Println("Filter needs output topic")
			return
		}
		log.Println("Making filter", fb)
		cb := makeFilter(fb)

		// subscribe to the broker to get all packets
		token := client.Subscribe("packet/#", 1, cb)
		token.Wait()
	}

	// subscribe to topic that creates filters
	token1 := client.Subscribe(fmt.Sprintf("make_filter/%s", c.String("topic")), 1, filter_cb)
	token1.Wait()
	//defaultFilterBundle := FilterBundle{
	//	ElideIfAny: []Filter{
	//		{
	//			SrcPort: "22",
	//		},
	//		{
	//			DstPort: "22",
	//		},
	//	},
	//	IncludeIfAll: []Filter{
	//		{
	//			Protocol: "tcp",
	//		},
	//	},
	//	Topic: "gabetest",
	//}
	//client.Publish("make_filter", 1, false, defaultFilterBundle.ToJSON())

	select {}

	log.Println(c.StringSlice("filter"))

	return nil
}

func makeView(c *cli.Context) error {
	client := getClient(c.String("broker"))
	f, err := os.Open(c.String("file"))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(f)
	var fb FilterBundle
	if err := dec.Decode(&fb); err != nil {
		return err
	}
	tok := client.Publish(fmt.Sprintf("make_filter/%s", fb.Topic), 1, false, fb.ToJSON())
	tok.Wait()
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
			Usage:  "Daemon to filter out the firehose. listens to 'make_filter'",
			Action: doFilter,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "broker, b",
					Usage: "MQTT broker",
					Value: "tcp://localhost:1883",
				},
				cli.StringFlag{
					Name:  "topic, t",
					Usage: "output topic",
					Value: "default",
				},
			},
		},
		{
			Name:   "makeview",
			Usage:  "Post a JSON file to MQTT 'make_filter' to create a new filtered view",
			Action: makeView,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "broker, b",
					Usage: "MQTT broker",
					Value: "tcp://localhost:1883",
				},
				cli.StringFlag{
					Name:  "file, f",
					Usage: "JSON file with filter. The Topic name selects the netview",
					Value: "filter1.json",
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
