package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

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
}

// matches packets in a stream that match this
type Filter struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol string
}

func (f Filter) ToJSON() []byte {
	b, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	return b
}

type FilterBundle struct {
	ElideIfAny   []Filter
	IncludeIfAny []Filter
	IncludeIfAll []Filter
	// topic to push filtered packets onto
	Topic string
}

func (fb FilterBundle) ToJSON() []byte {
	b, err := json.Marshal(fb)
	if err != nil {
		panic(err)
	}
	return b
}

func (fb *FilterBundle) MatchesPacket(pkt FlowPacket) bool {
	for _, eia := range fb.ElideIfAny {
		if eia.MatchesPacket(pkt) {
			return false
		}
	}
	if len(fb.IncludeIfAny) == 0 && len(fb.IncludeIfAll) == 0 {
		return true
	}

	for _, iia := range fb.IncludeIfAny {
		if iia.MatchesPacket(pkt) {
			return true
		}
	}
	matchesAll := false
	for _, iia := range fb.IncludeIfAll {
		if !iia.MatchesPacket(pkt) {
			return false
		} else {
			matchesAll = true
		}
	}
	return matchesAll
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
