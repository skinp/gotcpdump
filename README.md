# About

A dumbed down Go tcpdump that prints *some* data of each capture packets out to sdtout as a JSON document.

What is in the JSON blob:
* Hostname where we capture
* Timestamp of the capture
* Length of the packet
* Layer 3 type (IPv4, IPv6, ...)
* Source IP
* Destination IP
* Layer 4 type (TCP, UDP, ...)
* Source Port
* Destination Port

# Usage

    go get -u github.com/skinp/gotcpdump
    go install github.com/skinp/gotcpdump
    gotcpdump -S SNAPSHOT_LENGTH -d DEVICE_NAME -f PCAP_FILTER -p PROMISCIOUS_BOOL
