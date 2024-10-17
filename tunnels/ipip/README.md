
# ipip

The *ipip* program parses plain IPv4 as well as IP-in-IP packets. Any other packets are rejected(dropped).

A lookup, using as key the port/netdev the packet arrived on, is applied on table *fwd_table*. A match will either result in action *set_ipip* or *set_nh*. If an entry has no action or no entry is found, then by default *drop* action is assumed, meaning the packet will be dropped.

The *set_ipip* action facilitates pushing an IP-in-IP header and defining the egress port to send on. The *set_nh* action sets a programmed destination ethernet mac address and selects the egress port to send on.

From the above it should be noted that in our simple example - since our lookup key is based on the port on which the packet ingressed - to make it meaningful/observable we would need at least two entries: For one port which received IP-in-IP packets to program it with an action *set_nh* and for the other port that receives ip packets to program it with *set_nh*. Then we send IP-in-IP packets on one port and plain IP packets on another. Note, it is not wrong to send packets on a single port programmed with *set_ipip* action, but it will be less "observable" because we wont see the changed mac address that is provided by the *set_nh* action.

In our sample topology we have two ports - port0 and port1. As we shall show further down in the document, we will program port0 to execute *set_ipip* and port1 to execute *set_nh*.

## Setup Requirements

Make sure that the p4node basic container has already been created at this point (as per instructions found in [p4node](https://github.com/p4tc-dev/p4tc-examples-pub.git)). To run the sample described setup here requires 4 terminals, three terminals inside the container and one on the VM side

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node and setup path for TC binary and the path to the introspection file:

```
sudo ip netns exec p4node /bin/bash
TC="/usr/sbin/tc"
cd /home/vagrant/p4tc-examples-pub/tunnels/ipip/generated
export INTROSPECTION=.
```

run TC monitor:
`$TC mon p4 events`

### Terminal 2

First enter the container and then start tcpdump.

```
sudo ip netns exec p4node /bin/bash
DEV=port0
tcpdump -n -i $DEV -e
```

### Terminal 3

we will run commands to first load the prog and then do any runtime setup on this terminal.

First enter the container

```
sudo ip netns exec p4node /bin/bash
cd /home/vagrant/p4tc-examples-pub/tunnels/ipip
```

Compile the runtime parser and control blocks programs if you have not already

`make`

Make sure you have the introspection path setup correctly and load the ipip program

```
cd generated
export INTROSPECTION=.
TC="/usr/sbin/tc"
./ipip.template
```

Load the ext\_csum module:

`modprobe ext_csum`

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname ipip \
action bpf obj ipip_parser.o section p4tc/parse \
action bpf obj ipip_control_blocks.o section p4tc/main
```

### Terminal 4 (on the VM side, not inside container)

Try sending a packet which generates ARPs that will be dropped by the parser(observe tcpdump on terminal 2)..

`ping -I p4port0 10.0.1.2 -c 1`

Lets check some stats, below shows 3 packets dropped by the parser on <u>terminal 3</u>:

```
root@p4tc:/home/vagrant/p4tc-examples-pub/tunnels/ipip/generated# $TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname ipip
	action order 1: bpf ipip_parser.o:[p4tc/parse] id 29 name tc_parse_func tag b9fb4a22b6a18ba4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 63 sec used 11 sec firstused 21 sec
	Action statistics:
	Sent 140 bytes 4 pkt (dropped 4, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf ipip_control_blocks.o:[p4tc/main] id 31 name tc_ingress_func tag a5fadf8dff4d044d jited default-action pipe
	 index 2 ref 1 bind 1 installed 63 sec used 63 sec
	Action statistics:
	Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0
```

Note that the second program *ipip_control_blocks.o* is not hit at all..


Back to <u>terminal 4</u>, lets send a udp packet that will exercise the default entries

`sudo /home/vagrant/sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/tunnels/ipip/testpkt.yml`

And back on <u>terminal 3</u>, check the stats

```
root@p4tc:/home/vagrant/p4tc-examples-pub/tunnels/ipip/generated# $TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname ipip
	action order 1: bpf ipip_parser.o:[p4tc/parse] id 29 name tc_parse_func tag b9fb4a22b6a18ba4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 220 sec used 3 sec firstused 179 sec
        Action statistics:
	Sent 168 bytes 5 pkt (dropped 4, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf ipip_control_blocks.o:[p4tc/main] id 31 name tc_ingress_func tag a5fadf8dff4d044d jited default-action pipe
	 index 2 ref 1 bind 1 installed 220 sec used 3 sec firstused 3 sec
	Action statistics:
	Sent 28 bytes 1 pkt (dropped 1, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0
```

As can be observed this packet made it to the ipip control block but was dropped because there was no table entry match on the lookup.

Ok, on <u>terminal 3</u> lets create some entries (watch <u>terminal 1</u> for events):.

```
$TC p4ctrl create ipip/table/Main/fwd_table port port0 \
action set_ipip param src 2.2.2.2 param dst 2.4.4.8 param port port1
```

Essentially any IP packet coming in on port0 will have an ipip header pushed on top with src ip 2.2.2.2 and destination 2.4.4.8 and will be sent out on port1.

Lets dump and see how it looks like:

```
root@p4tc:/home/vagrant/tunnels/ipip# $TC p4ctrl get ipip/table/Main/fwd_table port port0

pipeline:  ipip(id 1)
 table: Main/fwd_table(id 1)entry priority 64000[permissions -RUD-PS-R--X--]
    entry key
     port id:1 size:32b type:dev exact fieldval  port0
    entry actions:
	action order 1: ipip/Main/set_ipip  index 1 ref 1 bind 1
	 params:
	  src type ipv4  value: 2.2.2.2 id 1
	  dst type ipv4  value: 2.4.4.8 id 2
	  port type dev  value: port1 id 3

    created by: tc (id 2)
    dynamic false
    created 56 sec    used 56 sec

```

On terminal 3 watch egressing port1 traffic:

`tcpdump -n -i port1 -e`

Now you can see the rewritten headers when you generate traffic on <u>terminal 4</u> as follows, first for plain ipv4:

`sudo /home/vagrant/sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/tunnels/ipip/testpkt.yml`

then for ipip encaped packets:

`sudo /home/vagrant/sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/tunnels/ipip/testpkt-ipip.yml`

Above packets are received on port1 and will be dropped by default because port1 has no entry in the table *fwd_table*. Check by running `$TC -s filter ls block 21 ingress` and see the stats on `action order 2: bpf ipip_control_blocks.o`.

Lets add an entry for packets incoming on port1 with action *set_nh* to pop the headers, set the mac address to *66:33:34:35:46:01* and send out on port1:

```
$TC p4ctrl create ipip/table/Main/fwd_table port port1 \
action set_nh param dmac 66:33:34:35:46:01 param port port0
```

Then repeat the traffic test:

`sudo /home/vagrant/sendpacket/sendpacket.py /home/vagrant/tunnels/ipip/testpkt-ipip.yml`

if you run tcpdump on port1, you will see:

```
root@p4tc:/home/vagrant/ipip# tcpdump -n -i port1 -e
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on port1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
16:19:19.917569 02:03:04:05:06:01 > 00:90:fb:65:d6:fe, ethertype IPv4 (0x0800), length 62: 10.0.0.1 > 10.99.0.1: 1.1.1.1.1235 > 1.3.3.7.4321: UDP, length 0
```

And on port0, you should see:

```
16:19:04.585514 02:03:04:05:06:01 > 66:33:34:35:46:01, ethertype IPv4 (0x0800), length 42: 1.1.1.1.1235 > 1.3.3.7.4321: UDP, length 0
```

## other commands

Delete the entry we created

`$TC p4ctrl delete ipip/table/Main/fwd_table port port0`

dump the table to check if any entry exists

`$TC p4ctrl get ipip/table/Main/fwd_table`

## General help on commands

Find out what tables exist:

*$TC p4ctrl create ipip/table/Main help*

```
Tables for pipeline ipip:
	  table name Main/fwd_table
	  table id 1
```

Lets get more details on *fwd_table*

*$TC p4ctrl create ipip/table/Main/fwd_table help*

```
root@p4tc:/home/vagrant/ipip# $TC p4ctrl create ipip/table/Main/fwd_table help
Key fields for table fwd_table:
	 key name port
	 key id 1
	 key type dev
	 key match type 	 exact

Actions for table fwd_table:
	  act name Main/set_ipip
	  act id 1

	  Params for Main/set_ipip:
	    param name src
	    param id 1
	    param type ipv4

	    param name dst
	    param id 2
	    param type ipv4

	    param name port
	    param id 3
	    param type dev


	  act name Main/set_nh
	  act id 2

	  Params for Main/set_nh:
	    param name dmac
	    param id 1
	    param type macaddr

	    param name port
	    param id 2
	    param type dev


	  act name Main/drop
	  act id 3

```

To cleanup
----------
./ipip.purge
