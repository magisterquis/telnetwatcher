TelnetWatcher
=============

Dumps the readable bytes of network traffic to stdout.  Originally meant to
monitor a telnet honeypot in real-time, now dumps any TCP/UDP traffic.

It's written for OpenBSD.  It'll probably work on other OSs with minor
modifications.

Examples
--------
Capture HTTP traffic:
```
$ doas out/telnetwatcher -p 80 em0
```

Capture keystrokes sent to a telnet server:
```bash
# telnetwatcher -t -p 23 em0 udp
```

Capture redis to a particular host:
```bash
# telnetwatcher em0 host 172.15.2.133 and tcp port 6379
```

Usage
-----
TelnetWatcher needs an interface on which to sniff traffic and a BPF filter to
select what to sniff.  It also needs to be run as root, but it will drop
privileges to nobody shortly after starting.

As an alternative to specifying a filter manually, TCP and UDP packets to or
from a particular port can be sniffed by specifying a port with `-p`.  The
direction to sniff can be restricted with `-t` and `-f`.  For example, to
only print the contents of packets going to port 23, the flags `-t -p 23` will
do much the same as specifying a filter like `dst port 23`.

Usage statement:
```
Usage: telnetwatcher [-tfPz] [-p port] interface [filter]

Prints the payloads of TCP and UDP packets, either to/from a specific port or
selected with a BPF filter.

Options:
  -p port  A single port on which to listen for TCP and UDP packets
  -t       With -p, only print the contents of packets going to the port
  -f       With -p, only print the contents of packets coming from the port
  -P       Put the interface in promiscuous mode
  -x       Print unprintable characters as <hex>
```

