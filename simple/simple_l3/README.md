# simple_l3

The *simple_l3* program first parses TCP packets. Any other packets are rejected(dropped). After the parser recognizes a TCP packet, the dst ip header is used as a lookup key for table *nh_table*. On a table hit the action *send_nh(srcmac, dstmac, port)* is executed to first set the programmed src and destination mac addresses and then redirect to a specified port. On a table miss the packet is dropped.

## Setup Requirements

Make sure that the p4node basic container has already been created at this point(as per instructions found in [p4node](https://github.com/p4tc-dev/p4tc-examples-pub.git)). To run the sample described setup here requires 4 terminals, three terminals inside the container and one on the VM side

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node:

`sudo ip netns exec p4node /bin/bash`

setup path for TC binary

`TC="/usr/sbin/tc"`

setup the path to where the json introspection file can be found..

```
`cd /home/vagrant/p4tc-examples-pub/simple/simple_l3/generated`
`export INTROSPECTION=.`
```

run TC monitor:

`$TC mon p4 events`

### Terminal 2

First enter the container and make sure you have the introspection path setup

`sudo ip netns exec p4node /bin/bash`

Now let's listen to traffic on port0

`DEV=port0`
`tcpdump -n -i $DEV -e`

### Terminal 3

we will run commands to first load the prog and then do any runtime setup.

First enter the container

`sudo ip netns exec p4node /bin/bash`
`cd /home/vagrant/p4tc-examples-pub/simple/simple_l3

Compile the parser and control blocks programs if you have not already

`make`

Make sure you have the introspection file set and load the simple_l3 program

```
cd generated/
export INTROSPECTION=.
TC="/usr/sbin/tc"
./simple_l3.template
```

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname simple_l3 \
action bpf obj simple_l3_parser.o section p4tc/parse \
action bpf obj simple_l3_control_blocks.o section p4tc/main
```

### Terminal 4 (on the VM side)

Try sending a message of packets which will be dropped by the parser (observe tcpdump on terminal 2)..

`ping -I p4port0 10.0.1.2 -c 1`

Let's check some stats, below shows 3 packets dropped by the parser on <u>terminal 3</u>:

```
$TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname simple_l3
	action order 1: bpf simple_l3_parser.o:[classifier/tc-parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 590 sec used 293 sec firstused 295 sec
 	Action statistics:
	Sent 84 bytes 3 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf simple_l3_control_blocks.o:[classifier/tc-ingress] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 590 sec used 590 sec
 	Action statistics:
	Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0
```

Note that the second program *simple_l3_control_blocks.o* is not hit at all..

Back to <u>terminal 4</u>, let's send a udp packet that will be accepted by the parser but dropped by the main program because of a table miss...

`cd /home/vagrant/p4tc-examples-pub/simple/simple_l3/`

`sudo ../../../sendpacket/sendpacket.py ./testpkt.yml`

And back on <u>terminal 3</u>, check the stats

```
root@p4tc:/home/vagrant/p4tc-examples-pub/simple/simple_l3/generated# $TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname simple_l3
	action order 1: bpf simple_l3_parser.o:[classifier/tc-parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 1082 sec used 16 sec firstused 787 sec
 	Action statistics:
	Sent 112 bytes 4 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf simple_l3_control_blocks.o:[classifier/tc-ingress] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 1082 sec used 16 sec firstused 16 sec
 	Action statistics:
	Sent 28 bytes 1 pkt (dropped 1, overlimits 0 requeues 0)
```

Ok, on <u>terminal 3</u> let's create an entry to match on the src address *10.0.0.1* and rewrite the srcmac to 10:00:00:02:aa:bb and dstmac 10:00:01:02:aa:bb  then send out on *port1*. 

Watch <u>terminal 1</u> for events.

```
$TC p4ctrl create simple_l3/table/ingress/nh_table \
dstAddr 10.99.0.1/32 \
action send_nh param port port1 param srcMac 10:00:00:02:aa:bb param dstMac 10:00:01:02:aa:bb
```

On terminal 3 watch egressing port1 traffic:

`tcpdump -n -i port1 -e`

Now you can see the rewritten mac address when you generate traffic on <u>terminal 4</u> as follows:

`sudo ../../sendpacket/sendpacket.py ./testpkt.yml`

## other commands

Delete the entry we created

`$TC p4ctrl delete simple_l3/table/ingress/nh_table dstAddr 10.99.0.1/32`

dump the table to check

`$TC p4ctrl get simple_l3/table/ingress/nh_table`

## General help on commands

*$TC p4ctrl create simple_l3/table help*

```
Tables for pipeline simple_l3:
	  table name ingress/nh_table
	  table id 1
```

*$TC p4ctrl create simple_l3/table/ingress/nh_table help*

```
Key fields for table nh_table:
	 key name dstAddr
	 key id 1
	 key type ipv4
	 key match type 	 exact

Actions for table nh_table:
	  act name ingress/send_nh
	  act id 1

	  Params for ingress/send_nh:
	    param name port
	    param id 1
	    param type dev

	    param name srcMac
	    param id 2
	    param type macaddr

	    param name dstMac
	    param id 3
	    param type macaddr

	  act name ingress/drop
	  act id 2
```

To cleanup
----------
To clean up you need to run the following script on Terminal 3, where the template was installed and the program was instantiated:
`./simple_l3.purge`
