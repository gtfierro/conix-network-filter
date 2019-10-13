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

### MQTT Broker

You need an MQTT Broker set up somewhere

### Scraper Daemon

You need at least one `scraper` daemon running to push network traffic onto the broker.
The `scraper` daemon takes as arguments a packet source and a BPF filter (usually good to keep this at `"ip"`). The packet source can be either a network interface (e.g. `eth0`) or a named pipe representing a remote packet source. To get a named pipe of packets from a remote machine, run the `get-remote-tcpdump.sh` script with the hostname and interface of the remote machine (e.g. `./get-remote-tcpdump.sh root@192.168.1.1 br-lan`); this will create a named pipe `/tmp/pcap` on your machine.

Now that you've established the packet source, you can run the `conix scrape` daemon.
You will likely need `sudo` for this; use the `-i` flag to point to the interace if it is local, or to the named pipe if it is remote:

```
# local interface
sudo ./conix scrape -i wlp0s20f3 -f "ip" -b tcp://localhost:1883

# remote interface
./get-remote-tcpdump.sh root@192.168.1.1  br-lan # separate terminal
./conix scrape -i /tmp/pcap -f "ip" -b tcp://localhost:1883
```

Leave this running.

It produces a stream of packets. The packet structure looks like this:

```json
{
    "SrcIP":"192.168.1.92",
    "DstIP":"151.101.188.134",
    "SrcPort":"59298",
    "DstPort":"443",
    "SrcMAC":"cc:4e:24:6d:5f:80",
    "DstMAC":""dc:ee:aa:be:f7:91,
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

You can use MQTT wildcards (`+` for 1, `#` for arbitrar suffix) to filter out what you want to subscribe to. For example, the "firehose" topic is `packet/#`


### Net View Daemon

The `netview` daemon produces curated streams of packets on a desired topic. The curated packets are determined by a mixture of WAVE permissions (coming soon) and simple JSON-based filters (implemented).

You will need one `netview` daemon per curated stream. The `--topic,-t` flag to `netview` gives the MQTT topic on which the curated stream will be publish. No need for sudo.

```
./conix netview -b tcp://localhost:1883 -t curated/nossh
```

### Registering Filters

To get a `netview` daemon to change what it filters, put your filters in a JSON file and send it to the broker with the `makeview` subcommand.

```json
# JSON filter: no SSH traffic
{
    "Topic": "curated/nossh",
    "ElideIfAny": [
        {"SrcPort": "22"},
        {"DstPort": "22"}
    ],
}
```

This will put all non-SSH packets on the topic `curated/nossh`

Register

```
./conix makeview -b tcp://localhost:1883 -f myfilter.json
```

The filter defined in the JSON file will *replace* whatever filter is currently configured for the `netview` daemon for that topic. If you choose a topic for which there is no `netview` daemon, nothing will happen.
