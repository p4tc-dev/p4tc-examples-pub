# digest

The *digest* program first parses ethernet <u>ipv4</u> packets. Any other packets are
rejected. After the parser recognizes an ipv4 packet, the src ip address is used as a lookup
key for table *nh_table*. On a table hit, the programmed action *send_nh(port, srcMac, dstMac)* instance is executed.
The action first sets the src and destination mac address, then redirects the packet to a specified port, sets the ingress_port, sets `send_digest` to true and redirects the packet. On a table miss the packet is simply dropped.
`my_ingress_metadata_t` will hold the port on where the packet arrived and `send_digest`. `send_digest` signals to the deparser to send a digest message to user space. This digest message will hold the source mac address and the port where the packet arrived:

```
struct mac_learn_digest_t {
    @tc_type("macaddr") bit<48> srcAddr;
    @tc_type("dev") PortId_t ingress_port;
};
```

## Setup Requirements

Make sure that the p4node basic container has already been created at this point(as per instructions found in [p4node](https://github.com/p4tc-dev/p4tc-examples-pub.git)). To run the sample described setup here requires 4 terminals, three terminals inside the container and one on the VM side to generate traffic.

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node:

`sudo ip netns exec p4node /bin/bash`

setup path for TC binary

`TC="/usr/sbin/tc"`

setup the path to where the json introspection file can be found..

```
cd /home/vagrant/p4tc-examples-pub/digest/generated
export INTROSPECTION=.
```
run TC monitor:
`$TC mon p4 events`

### Terminal 2 (observation of p4 digest events on p4node).

First enter the container and make sure you have the introspection path setup

Enter the container p4node:

`sudo ip netns exec p4node /bin/bash`

setup path for TC binary

`TC="/usr/sbin/tc"`

setup the path to where the json introspection file can be found..

```
cd /home/vagrant/p4tc-examples-pub/digest/generated
export INTROSPECTION=.
```

run TC monitor for digest events:
`$TC mon p4 digest`

### Terminal 3 (observes incoming traffic into p4node)

First enter the container and make sure you have the introspection path setup

`sudo ip netns exec p4node /bin/bash`

Now let's listen to traffic on port0

```
DEV=port0
tcpdump -n -i $DEV -e
```

### Terminal 4 (to instantiate and runtime control the program)

We will run commands to first load the prog and then do required runtime setup.

First enter the container

```
sudo ip netns exec p4node /bin/bash
cd /home/vagrant/p4tc-examples-pub/digest
```

```
modprobe ext_Digest
```

Compile the parser and control blocks programs if you have not already

`make`

Make sure you have the introspection path setup and load the *digest* program

```
cd generated
export INTROSPECTION=.
TC="/usr/sbin/tc"
./digest.template
```

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname digest \
action bpf obj digest_parser.o section p4tc/parse \
action bpf obj digest_control_blocks.o section p4tc/main
```

### Terminal 5 (on the VM side)

Try sending a message of packets which will be dropped by the parser (observe tcpdump on terminal 3)..

`ping -I p4port0 10.0.1.2 -c 1`

Let's check some stats, below shows 3 packets dropped by the parser on <u>terminal 3</u>:

```
$TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname digest
	action order 1: bpf digest_parser.o:[p4tc/parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	index 1 ref 1 bind 1 installed 590 sec used 293 sec firstused 295 sec
	Action statistics:
	Sent 84 bytes 3 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf digest_control_blocks.o:[p4tc/main] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 590 sec used 590 sec
	Action statistics:
	Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0
```

Ok, back on <u>terminal 4</u> let's create an entry to match on the dst address *10.0.0.2* and rewrite the src mac to *00:01:02:03:04:05* and dst mac *06:07:08:09:11:12* then send out on *port1* - watch <u>terminal 1</u> for events.

```
$TC p4ctrl create digest/table/ingress/nh_table \
dstAddr 10.0.0.2 \
action send_nh param port port1 param srcMac 06:07:08:09:11:12 param dstMac 00:01:02:03:04:05
```

On <u>terminal 4</u> watch *port1* traffic (recall that you are watching incoming traffic on <u>terminal 2</u> on *port0*):

`tcpdump -n -i port1 -e`

Now you can see the rewritten mac address when you generate traffic on terminal 5 as follows:

```
cd /home/vagrant/p4tc-examples-pub/digest

sudo ../../sendpacket/sendpacket.py ./testpkt.yml
```

On <u>terminal 2</u> look for the digest event

## General help on runtime CLI

First just dump all possible tables in this program

*$TC p4ctrl create digest/table help*

```
Tables for pipeline digest:
	  table name ingress/nh_table
	  table id 1
```

As we can see, there is only one with a path ingress/nh_table

Now let's get help on the *create* command for this table:

*$TC p4ctrl create digest/table/ingress/nh_table help*

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

Above is indicating the table has a key called dstAddr which is of type ipv4 address and that it takes one action:
  - *send_nh* which takes 3 params 1)*port*, a linux netdev 2) *srcMac*, a mac address 3) *dstMac*, also a mac address

And help on the *delete* command:

*$TC p4ctrl delete digest/table/ingress/nh_table help*

```
Key fields for table nh_table:
	 key name dstAddr
	 key id 1
	 key type ipv4
	 key match type  exact
```

This shows the key name "dstAddr" as an exact IPv4 address.
Example to delete the entry we created:

*$TC p4ctrl delete digest/table/ingress/nh_table dstAddr 10.0.0.2*

And to delete/flush the whole table:

*$TC p4ctrl delete digest/table/ingress/nh_table

And help on the *get* command:

*$TC p4ctrl get digest/table/ingress/nh_table help*

```
Key fields for table nh_table:
	 key name dstAddr
	 key id 1
	 key type ipv4
	 key match type 	 exact
```

This shows the key name "dstAddr" as an exact IPv4 address.
For example to retrieve the entry we created using our key of 10.0.0.2:

*$TC p4ctrl get digest/table/ingress/nh_table dstAddr 10.0.0.2*

Note, we can dump the whole table as such:

*$TC p4ctrl get digest/table/ingress/nh_table*


To cleanup
----------
To clean up you need to run the following script on Terminal 4, where the template was installed and the program was instantiated:

`./digest.purge`
