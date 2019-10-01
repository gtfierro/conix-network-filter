# Network Monitor

## Building

Requirements:
- [Go](https://golang.org/dl/)
- libpcap (`sudo apt install libpcap-dev`)

```
go build
```

## Documentation

This is a simple network monitoring tool. It uses libpcap to read packets off of a local interface, formats them into a simple representation of a network flow and publishes these on an MQTT broker (JSON-serialized)

The packet structure looks like this:

```json
{
    "SrcIP":"192.168.1.92",
    "DstIP":"151.101.188.134",
    "SrcPort":"59298",
    "DstPort":"443",
    "Protocol":"tcp",
    "Payload":""
}
```

`Payload` is not currently populated.

These are published on topics of the following template:

```
packet/<src ip>/<dst ip>/<src port>/<dst port>/<protocol>
```

for the above packet this is

```
packet/192.168.1.92/151.101.188.134/59298/443/tcp
```

You can use MQTT wildcards (`+` for 1, `#` for arbitrar suffix) to filter out what you want to subscribe to.
