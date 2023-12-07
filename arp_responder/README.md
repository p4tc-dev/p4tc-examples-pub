# arp_respond

The *arp_respond* program first parses ethernet ARP packets. Any other packets are
rejected. After the parser recognizes an ARP packets, the requested IP is used as a lookup
key for table arp_table. arp_table maps the requested IP to a MAC address. On a table hit,
the action arp_reply() is executed to build the arp response with programmed MAC address.
The response is sent back to the port in which the request was received from.
On a table miss the packet is dropped.

## Setup Requirements

Make sure that the p4node basic container has already been created at this point (as per instructions found in [p4node](https://github.com/p4tc-dev/p4tc-examples-pub.git)). To run the sample described setup here requires 4 terminals, three terminals inside the container and one on the VM side

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node:

`sudo ip netns exec p4node /bin/bash`

setup path for TC binary

`TC="/usr/sbin/tc"`

setup the path to where the json introspection file can be found..

```
cd /home/vagrant/p4tc-examples-pub/arp_responder/generated
export INTROSPECTION=.
```

run TC monitor:
`$TC mon`

### Terminal 2

First enter the container and make sure you have the introspection path setup

`sudo ip netns exec p4node /bin/bash`

Now let's listen to traffic on port0

`DEV=port0`
`tcpdump -n -i $DEV -e`

### Terminal 3

we will run commands to first load the prog and then do any runtime setup.

First enter the container and make sure you have the introspection path setup

```
sudo ip netns exec p4node /bin/bash
cd /home/vagrant/p4tc-examples-pub/arp_responder/generated
export INTROSPECTION=.
TC="/usr/sbin/tc"
```

Load the arp_respond program

`./arp_respond.template`

Compile the parser and control blocks programs if you have not already

`make`

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname arp_respond \
action bpf obj arp_respond_parser.o section classifier/tc-parse \
action bpf obj arp_respond_control_blocks.o section classifier/tc-ingress
```

### Terminal 4 (on the VM side)

Try sending a message of packets which will be dropped by the parser (observe tcpdump on terminal 2)..

`ping -I p4port0 10.0.0.20 -c 1`

Let's check some stats, below shows 3 packets dropped by the parser on terminal 3:

```
$TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname arp_respond
	action order 1: bpf arp_respond_parser.o:[classifier/tc-parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 590 sec used 293 sec firstused 295 sec
 	Action statistics:
	Sent 84 bytes 3 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf arp_respond_control_blocks.o:[classifier/tc-ingress] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 590 sec used 590 sec
 	Action statistics:
	Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0
```

Back to terminal 4, let's send a udp packet that will be accepted by the parser but dropped by the main program because of a table miss...

And back on terminal 3, check the stats

```
root@p4tc:/home/vagrant/p4tc-examples-pub/arp_respond# $TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname arp_respond
	action order 1: bpf arp_respond_parser.o:[classifier/tc-parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 1082 sec used 16 sec firstused 787 sec
 	Action statistics:
	Sent 112 bytes 4 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf arp_respond_control_blocks.o:[classifier/tc-ingress] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 1082 sec used 16 sec firstused 16 sec
 	Action statistics:
	Sent 28 bytes 1 pkt (dropped 1, overlimits 0 requeues 0)
```

Ok, on terminal 3 let's create an entry to match on the src address 10.0.0.20 which will be responded to with MAC 00:01:02:03:04:20

```
$TC p4ctrl create arp_respond/table/ingress/arp_table \
IPaddr 10.0.0.20/32 action arp_reply param rmac 00:01:02:03:04:20
```

Try the ping again on terminal 4...

`ping -I p4port0 10.0.0.20 -c 1`

On terminal 2 you can see the ARP response when you generate traffic..
Note: The arp will resolve and ping will be sent but there will be no response back so it will fail..

If you dump the neighbors on the host now, you will see the resolved address:

```
vagrant@p4tc:~$ ip n ls
10.0.2.3 dev eth0 lladdr 52:54:00:12:35:03 STALE
10.0.0.20 dev p4port0 lladdr 00:01:02:03:04:20 REACHABLE
10.0.2.2 dev eth0 lladdr 52:54:00:12:35:02 REACHABLE
```

## other commands

Retrieve the entry we created

`$TC p4ctrl get arp_respond/table/ingress/arp_table srcAddr 10.0.0.20/32`

Delete the entry we created

`$TC p4ctrl delete arp_respond/table/ingress/arp_table srcAddr 10.0.0.20/32`

dump the table to check

`$TC p4ctrl get arp_respond/table/ingress/arp_table`

To cleanup
----------
To clean up you need to run the following script on Terminal 3, where the template was installed and the program was instantiated:
`./arp_respond.purge`
