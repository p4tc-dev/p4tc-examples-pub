# redirect_l2

The *redirect_l2* program first parses ethernet <u>ipv4</u> packets. Any other packets are
rejected. After the parser recognizes an ipv4 packet, the src ip address is used as a lookup
key for table *nh_table*. On a table hit, the programmed action *send_nh(srcmac, dstmac, port)* instance is executed. The action first sets the src and destination mac address and then redirects the packet to a specified port. On a table miss the packet is simply dropped.

## Setup Requirements

Make sure that the p4node basic container has already been created at this point(as per instructions found in [p4node](https://github.com/p4tc-dev/p4tc-examples-pub.git)). To run the sample described setup here requires 4 terminals, three terminals inside the container and one on the VM side to generate traffic.

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node:

`sudo ip netns exec p4node /bin/bash`

setup path for TC binary

`TC="/usr/sbin/tc"`

setup the path to where the json introspection file can be found..

```
cd /home/vagrant/p4tc-examples-pub/simple/redirect_l2/generated
export INTROSPECTION=.
```
run TC monitor:
`$TC mon p4 events`

### Terminal 2 (observes incoming traffic into p4node)

First enter the container and make sure you have the introspection path setup

`sudo ip netns exec p4node /bin/bash`

Now let's listen to traffic on port0

```
DEV=port0
tcpdump -n -i $DEV -e
```

### Terminal 3 (to instantiate and runtime control the program)

We will run commands to first load the prog and then do required runtime setup.

First enter the container

```
sudo ip netns exec p4node /bin/bash
cd /home/vagrant/p4tc-examples-pub/simple/redirect_l2
```

Compile the parser and control blocks programs if you have not already

`make`

Make sure you have the introspection path setup and load the *redirect_l2* program

```
cd generated
export INTROSPECTION=.
TC="/usr/sbin/tc"
./redirect_l2.template
```

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname redirect_l2 \
action bpf obj redirect_l2_parser.o section p4tc/parse \
action bpf obj redirect_l2_control_blocks.o section p4tc/main
```

### Terminal 4 (on the VM side)

Try sending a message of packets which will be dropped by the parser (observe tcpdump on terminal 2)..

`ping -I p4port0 10.0.1.2 -c 1`

Let's check some stats, below shows 3 packets dropped by the parser on <u>terminal 3</u>:

```
$TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname redirect_l2
	action order 1: bpf redirect_l2_parser.o:[classifier/tc-parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 590 sec used 293 sec firstused 295 sec
 	Action statistics:
	Sent 84 bytes 3 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf redirect_l2_control_blocks.o:[classifier/tc-ingress] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 590 sec used 590 sec
 	Action statistics:
	Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0
```

Note that the main program (redirect_l2_control_blocks.o) did not receive any packet since they were dropped by the parser.

Back to <u>terminal 4</u>, let's send a udp packet that will be accepted by the parser but dropped by the main program because of a table miss...

`cd /home/vagrant/p4tc-examples-pub/simple/redirect_l2`

`sudo /home/vagrant/sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/simple/redirect_l2/testpkt.yml`

And back on <u>terminal 3</u>, check the stats

```
root@p4tc:/home/vagrant/p4tc-examples-pub/simple/redirect_l2/generated# $TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname redirect_l2
	action order 1: bpf redirect_l2_parser.o:[classifier/tc-parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	 index 1 ref 1 bind 1 installed 1082 sec used 16 sec firstused 787 sec
 	Action statistics:
	Sent 112 bytes 4 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf redirect_l2_control_blocks.o:[classifier/tc-ingress] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 1082 sec used 16 sec firstused 16 sec
 	Action statistics:
	Sent 28 bytes 1 pkt (dropped 1, overlimits 0 requeues 0)
```

Ok, back on <u>terminal 3</u> let's create an entry to match on the src address *10.0.0.1* and rewrite the src mac to *00:01:02:03:04:05* and dst mac *06:07:08:09:11:12* then send out on *port1* - watch <u>terminal 1</u> for events.

```
$TC p4ctrl create redirect_l2/table/ingress/nh_table \
srcAddr 10.0.0.1/32 \
action send_nh param port_id port1 param dmac 00:01:02:03:04:05 param smac 06:07:08:09:11:12
```

On <u>terminal 3</u> watch *port1* traffic (recall that you are watching incoming traffic on <u>terminal 2</u> on *port0*):

`tcpdump -n -i port1 -e`

Now you can see the rewritten mac address when you generate traffic on terminal 4 as follows:

`sudo /home/vagrant/sendpacket/sendpacket.py ./testpkt.yml`

## General help on runtime CLI

First just dump all possible tables in this program

*$TC p4ctrl create redirect_l2/table help*

```
Tables for pipeline redirect_l2:
	  table name ingress/nh_table
	  table id 1
```

As we can see, there is only one with a path ingress/nh_table

Now let's get help on the *create* command for this table:

*$TC p4ctrl create redirect_l2/table/ingress/nh_table help*

```
Key fields for table nh_table:
	 key name srcAddr
	 key id 1
	 key type ipv4
	 key match type 	 exact

Actions for table nh_table:
	  act name ingress/send_nh
	  act id 1

	  Params for ingress/send_nh:
	    param name port_id
	    param id 1
	    param type dev

	    param name dmac
	    param id 2
	    param type macaddr

	    param name smac
	    param id 3
	    param type macaddr
```

Above is indicating the table has a key called srcAddr which is type ipv4 address and that it takes one action:
  - *send_nh* which takes 3 params 1)*port_id*, a linux netdev 2) *dmac*, a mac address 3) *smac*, also a mac address

And help on the *delete* command:

*$TC p4ctrl delete redirect_l2/table/ingress/nh_table help*

```
Key fields for table nh_table:
	 key name srcAddr
	 key id 1
	 key type ipv4
	 key match type  exact
```

This shows the key name "srcAddr" as an exact IPv4 address.
Example to delete the entry we created:

*$TC p4ctrl delete redirect_l2/table/ingress/nh_table srcAddr 10.0.0.1/32*

And to delete/flush the whole table:

*$TC p4ctrl delete redirect_l2/table/ingress/nh_table

And help on the *get* command:

*$TC p4ctrl get redirect_l2/table/ingress/nh_table help*

```
Key fields for table nh_table:
	 key name srcAddr
	 key id 1
	 key type ipv4
	 key match type 	 exact
```

This shows the key name "srcAddr" as an exact IPv4 address.
For example to retrieve the entry we created using our key of 10.0.0.1:

*$TC p4ctrl get redirect_l2/table/ingress/nh_table srcAddr 10.0.0.1/32*

Note, we can dump the whole table as such:

*$TC p4ctrl get redirect_l2/table/ingress/nh_table*


To cleanup
----------
To clean up you need to run the following script on Terminal 3, where the template was installed and the program was instantiated:

`./redirect_l2.purge`
