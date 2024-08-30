# routing

The *routing* program parses IPv4 packets. Any other packets are rejected(dropped).

An invalid IPv4 packet with a ttl <= 1 is dropped; otherwise the packet's destination IP address is used to look up the table *fib_table*. On a table hit, the matched entry will utilized an action *set_nhid* programmed for the table entry. The *set_nhid* action sets a *nh_index* metadata value which is used downstream as a key to lookup the table *nh_table*. On a table miss the default miss action, *set_nhid*, which sets the *nh_index* metadata value to 0 is used.

After the *fib_table* exercise is done, the *nh_table* is then looked up using the previously retrieved *nh_index* as the key. On a miss, the default  miss action, *drop*, is executed. On a hit, the entry's programmed *set_nh* is executed. The *set_nh* action sets the destination MAC address and the egress port to send the packet to.

From the above we can see that we can have a default route using index 0 of the *nh_table*.
But: In order to get a default route entry to work, one must populate the *nh_table* index 0 entry, see example further below. If *nh_table* index 0 is not populated then the packet will be dropped upon a miss on *fib_table*.

The ttl decrement and checksum computation is done on the deparser stage before the packet is sent out.

## Setup Requirements

Make sure that the p4node basic container has already been created at this point (as per instructions found in [p4node](https://github.com/p4tc-dev/p4tc-examples-pub.git)).  To run the sample described setup requires 4 terminals, three terminals inside the container and one on the VM side.

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node and setup path for TC binary and the path to the introspection file:

```
sudo ip netns exec p4node /bin/bash
TC="/usr/sbin/tc"
cd /home/vagrant/p4tc-examples-pub/routing/generated
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

we will run commands to first load the prog and then do any runtime setup.

First enter the container

```
sudo ip netns exec p4node /bin/bash
cd /home/vagrant/p4tc-examples-pub/routing
```

Compile the runtime parser and control blocks programs if you have not already

`make`

Make sure you have the introspection path setup and load the routing program

```
cd generated/
export INTROSPECTION=.
TC="/usr/sbin/tc"
./routing.template
```

Load the ext\_csum module:

`modprobe ext_csum`

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname routing \
action bpf obj routing_parser.o section p4tc/parse \
action bpf obj routing_control_blocks.o section p4tc/main
```

### Terminal 4 (on the VM side)

Try sending a message of packets which generates ARPs that will be dropped by the parser(observe tcpdump on terminal 2)..

`ping -I p4port0 10.0.1.2 -c 1`

Lets check some stats, below shows 3 packets dropped by the parser on <u>terminal 3</u>:

```
$TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname routing
	action order 1: bpf routing_parser.o:[p4tc/parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 590 sec used 293 sec firstused 295 sec
	Action statistics:
	Sent 84 bytes 3 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf routing_control_blocks.o:[p4tc/main] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 590 sec used 590 sec
	Action statistics:
	Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0
```

Note that the second program *routing_control_blocks.o* is not hit at all because the parser dropped the non-IP arp packets.

Back to <u>terminal 4</u>, lets send a udp packet that will exercise the default entries

`sudo sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/routing/testpkt.yml`

And back on <u>terminal 3</u>, check the stats

```
root@p4tc:/home/vagrant/p4tc-examples-pub/routing/generated# $TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname routing
	action order 1: bpf routing_parser.o:[p4tc/parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 1082 sec used 16 sec firstused 787 sec
	 Action statistics:
	Sent 112 bytes 4 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf routing_control_blocks.o:[p4tc/main] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 1082 sec used 16 sec firstused 16 sec
	 Action statistics:
	Sent 28 bytes 1 pkt (dropped 1, overlimits 0 requeues 0)
```

As you can see above the packet made it through the parser but was dropped at the control block. This is expected: Packets that don't match on the *fib_table* will have the next hop index set to 0. But since the default entry(index 0) in the table *nh_table* has not been programmed the default action is to drop.

Ok, Lets demonstrate default routes by populating index 0 of *nh_table*

```
$TC p4ctrl create routing/table/Main/nh_table nh_index 0 \
action set_nh param dmac aa:bb:cc:dd:ee:ff param port port1
```

If you watch TC monitor in terminal 1, you will see an event being generated for this entry:

```
created pipeline:  routing(id 1)
 table: Main/nh_table(id 1)entry priority 64000[permissions -RUD-PS-R--X--]
    entry key
     nh_index id:1 size:32b type:bit32 exact fieldval  0/0xffffffff
    entry actions:
	action order 1: routing/Main/set_nh  index 1 ref 1 bind 1
	 params:
	  dmac type macaddr  value: aa:bb:cc:dd:ee:ff id 1
	  port type dev  value: port1 id 2

    created by: tc (id 2)
    dynamic false

```

Now repeat the test from earlier from the VM side:
`sudo sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/routing/testpkt.yml`

You should see this packet being forwarded to port1 on tcpdump.

```
root@p4tc:/home/vagrant# tcpdump -n -i port1 -e
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on port1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
13:46:16.441857 02:03:04:05:06:01 > aa:bb:cc:dd:ee:ff, ethertype IPv4 (0x0800), length 42: 11.0.0.1.1235 > 10.99.0.1.4321: UDP, length 0
```

Our debug output on the filter now looks as follows:
```
root@p4tc:/home/vagrant/p4tc-examples-pub/routing/generated# $TC -s filter ls block 21 ingress 
filter protocol all pref 10 p4 chain 0 
filter protocol all pref 10 p4 chain 0 handle 0x1 pname routing 
	action order 1: bpf routing_parser.o:[p4tc/parse] id 78 name tc_parse_func tag 4b0873fea2961183 jited default-action pipe
	 index 1 ref 1 bind 1 installed 732 sec used 480 sec firstused 712 sec
 	Action statistics:
	Sent 112 bytes 4 pkt (dropped 3, overlimits 0 requeues 0) 
	backlog 0b 0p requeues 0

	action order 2: bpf routing_control_blocks.o:[p4tc/main] id 80 name tc_ingress_func tag fe7824eaa74d0f2b jited default-action pipe
	 index 2 ref 1 bind 1 installed 732 sec used 480 sec firstused 480 sec
 	Action statistics:
	Sent 56 bytes 2 pkt (dropped 1, overlimits 0 requeues 0) 
	backlog 0b 0p requeues 0
```

Observe now we have two packets that are seen by the control block (of which one was dropped).


next, on <u>terminal 3</u> lets create some entries (watch <u>terminal 1</u> for events):.

- on *nh_table* to match on index *1* with action *set_nh* action setting the nexthop destination MAC to 13:37:13:37:13:37 and then to send out on *port1*.

```
$TC p4ctrl create routing/table/Main/nh_table nh_index 1 \
action set_nh param dmac 13:37:13:37:13:37 param port port1
```

- on *fib_table* to match on the prefix *10.0.0.0/8* with action *set_nhid* setting the nexthop id index to 1.

```
$TC p4ctrl create routing/table/Main/fib_table  prefix 10.0.0.0/8 \
action set_nhid param index 1
```

On terminal 3 watch egressing port1 traffic:

`tcpdump -n -i port1 -e`

Now you can see the rewritten mac address when you generate traffic on <u>terminal 4</u> as follows:

`sudo sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/routing/generated/testpkt.yml`

Let's dump the *nh_table*

```
root@p4tc:/home/vagrant/p4tc-examples-pub/routing/generated# $TC p4ctrl get routing/table/Main/nh_table
pipeline:  routing(id 1)
 table: Main/nh_table(id 1)entry priority 64000[permissions -RUD-PS-R--X--]
    entry key
     nh_index id:1 size:32b type:bit32 exact fieldval  1/0xffffffff
    entry actions:
	action order 1: routing/Main/set_nh  index 2 ref 1 bind 1
	 params:
	  dmac type macaddr  value: 13:37:13:37:13:37 id 1
	  port type dev  value: port1 id 2

    created by: tc (id 2)
    dynamic false
    created 20338 sec  used 39 sec

 table: Main/nh_table(id 1)entry priority 64000[permissions -RUD-PS-R--X--]
    entry key
     nh_index id:1 size:32b type:bit32 exact fieldval  0/0xffffffff
    entry actions:
	action order 1: routing/Main/set_nh  index 1 ref 1 bind 1
	 params:
	  dmac type macaddr  value: aa:bb:cc:dd:ee:ff id 1
	  port type dev  value: port1 id 2

    created by: tc (id 2)
    dynamic false
    created 20784 sec  used 597 sec
```

## other commands

Delete the entry we created

`$TC p4ctrl delete routing/table/Main/fib_table prefix 10.0.0.0/8`

dump the table to check if any entry

`$TC p4ctrl get routing/table/Main/nh_table`

## General help on commands

Find out what tables exist:

*$TC p4ctrl create  routing/table/Main help*

```
Tables for pipeline routing:
	  table name Main/fib_table
	  table id 2

	  table name Main/nh_table
	  table id 1
```

Lets get more details on *fib_table*

*$TC p4ctrl create routing/table/Main/fib_table help*

```
Key fields for table fib_table:
	 key name prefix
	 key id 1
	 key type ipv4
	 key match type 	 lpm

Actions for table fib_table:
	  act name Main/set_nhid
	  act id 3

	  Params for Main/set_nhid:
	    param name index
	    param id 1
	    param type bit32

```

To cleanup
----------
./routing.purge
