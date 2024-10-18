# Drop Reason

This program demonstrates how to capture events from the datapath and log them as events to the control plane.
In this case we capture the reason why packets are dropped, what port they arrived on and what src mac address was observed on the packet.
Packets could be dropped for two reasons:

- The parser was unable to parse the packet
- Unable to find a matching entry on lookup of table nh\_table.

The *drop_reason* program first parses ethernet <u>ipv4</u> packets.
Any other packets are rejected and will result in a drop_reason digest event being sent with the packet's `ingress_port`, src mac address and drop reason set to `parser_rejected`.
After the parser recognizes an ipv4 packet, the src ip address is used as a lookup
key for table *nh_table*. On a table hit, the programmed action *send_nh(port, srcMac, dstMac)* instance is executed.
The action first sets the src and destination mac address, then redirects the packet to a specified port.
On a table miss, the program sets the `ingress_port`, `send_digest` to true, drop reason to `table_miss` and marks the packet to be dropped.
`my_ingress_metadata_t` will hold the port on where the packet arrived, the drop reason and `send_digest`.
`send_digest` signals the deparser to send a digest message to user space.
This digest message will hold the source mac address, the port where the packet arrived and the drop reason:

```
struct mac_learn_digest_t {
    @tc_type("macaddr") bit<48> srcAddr;
    @tc_type("dev") PortId_t ingress_port;
    DROP_REASON drop_reason;
};
```

## Setup Requirements

Make sure that the p4node basic container has already been created at this point(as per instructions found in [p4node](https://github.com/p4tc-dev/p4tc-examples-pub.git)). To run the sample described setup here requires 5 terminals, four terminals inside the container and one on the VM side to generate traffic.

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node:

`sudo ip netns exec p4node /bin/bash`

setup path for TC binary

`TC="/usr/sbin/tc"`

setup the path to where the json introspection file can be found..

```
cd /home/vagrant/p4tc-examples-pub/drop_reason/generated
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
cd /home/vagrant/p4tc-examples-pub/drop_reason/generated
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
cd /home/vagrant/p4tc-examples-pub/drop_reason
```

Compile the parser and control blocks programs if you have not already

`make`

Make sure you have the introspection path setup and load the *digest* program

```
cd generated
export INTROSPECTION=.
TC="/usr/sbin/tc"
./drop_reason.template
```

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname drop_reason \
action bpf obj drop_reason_parser.o section p4tc/parse \
action bpf obj drop_reason_control_blocks.o section p4tc/main
```

### Terminal 5 (on the VM side)

Try sending a message of packets which will be dropped by the parser ..

`ping -I p4port0 10.0.1.2 -c 1`

Let's check some stats, below shows 3 packets dropped by the parser on <u>terminal 3</u>:

```
$TC -s filter ls block 21 ingress
filter protocol all pref 10 p4 chain 0
filter protocol all pref 10 p4 chain 0 handle 0x1 pname drop_reason
	action order 1: bpf drop_reason_parser.o:[p4tc/parse] id 92 name tc_parse_func tag 1bd66321c5ad54e4 jited default-action pipe
	index 1 ref 1 bind 1 installed 590 sec used 293 sec firstused 295 sec
	Action statistics:
	Sent 84 bytes 3 pkt (dropped 3, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0

	action order 2: bpf drop_reason_control_blocks.o:[p4tc/main] id 94 name tc_ingress_func tag 42e6e971daa41152 jited default-action pipe
	 index 2 ref 1 bind 1 installed 590 sec used 590 sec
	Action statistics:
	Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
	backlog 0b 0p requeues 0
```

On <u>terminal 2</u> look for the digest event:

```
total exts 0
Added extern 
        extern order 1:
          Extern kind Digest
          Extern instance Ingress_Deparser.digest_inst
          Extern key 0
          Params:

          srcAddr  id 2 type macaddr value: 10:00:00:01:aa:bb
          ingress_port  id 3 type dev value: port0
          drop_reason  id 4 type bit8  value: 1
`` 

drop_reason `1` means `PARSER_REJECTED`

Back on terminal 5, generate a TCP packet:

`sudo /home/vagrant/sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/drop_reason/testpkt.yml`

Again on <u>terminal 2</u> look for the digest event:

```
total exts 0
Added extern 
        extern order 1:
          Extern kind Digest
          Extern instance Ingress_Deparser.digest_inst
          Extern key 0
          Params:

          srcAddr  id 2 type macaddr value: 02:03:04:05:06:01
          ingress_port  id 3 type dev value: port0
          drop_reason  id 4 type bit8  value: 2
```

This time the drop_reason is set to `2`, which means `TABLE_MISS`

Ok, back on <u>terminal 4</u> let's create an entry to match on the dst address *10.0.0.2* and rewrite the src mac to *00:01:02:03:04:05* and dst mac *06:07:08:09:11:12* then send out on *port1*

```
$TC p4ctrl create drop_reason/table/ingress/nh_table \
dstAddr 10.0.0.2 \
action send_nh param port port1 param srcMac 06:07:08:09:11:12 param dstMac 00:01:02:03:04:05
```

If you look at <u>terminal 1</u>, a table create event will be emitted:

```
created pipeline:  drop_reason(id 1)
 table: ingress/nh_table(id 1)entry priority 64000[permissions -RUD-PS-R--X--]
    entry key
     dstAddr id:1 size:32b type:ipv4 exact fieldval  10.0.0.2/32
    entry actions:
        action order 1: drop_reason/ingress/send_nh  index 2 ref 1 bind 1
         params:
          port type dev  value: port1 id 1

          srcMac type macaddr  value: 06:07:08:09:11:12 id 2

          dstMac type macaddr  value: 00:01:02:03:04:05 id 3


    created by entity: tc (id 2)
    create by pid: 3921
    created by process: tc
    dynamic false

    tmpl created false
```

On <u>terminal 4</u> watch *port1* traffic (recall that you are watching incoming traffic on <u>terminal 2</u> on *port0*):

`tcpdump -n -i port1 -e`

Now you can send the rewritten mac address when you generate traffic on terminal 5 as follows:

`sudo /home/vagrant/sendpacket/sendpacket.py /home/vagrant/p4tc-examples-pub/drop_reason/testpkt.yml`

Back on <u>terminal 4<\u>:

```
21:32:09.362397 06:07:08:09:11:12 > 00:01:02:03:04:05, ethertype IPv4 (0x0800), length 54: 10.0.0.1.1235 > 10.0.0.2.4321: Flags [S], seq 0, win 8192, length 0
```

## General help on runtime CLI

First just dump all possible tables in this program

*$TC p4ctrl create drop_reason/table help*

```
Tables for pipeline drop_reason:
	  table name ingress/nh_table
	  table id 1
```

As we can see, there is only one with a path ingress/nh_table

Now let's get help on the *create* command for this table:

*$TC p4ctrl create drop_reason/table/ingress/nh_table help*

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

*$TC p4ctrl delete drop_reason/table/ingress/nh_table help*

```
Key fields for table nh_table:
	 key name dstAddr
	 key id 1
	 key type ipv4
	 key match type  exact
```

This shows the key name "dstAddr" as an exact IPv4 address.
Example to delete the entry we created:

*$TC p4ctrl delete drop_reason/table/ingress/nh_table dstAddr 10.0.0.2*

And to delete/flush the whole table:

*$TC p4ctrl delete drop_reason/table/ingress/nh_table

And help on the *get* command:

*$TC p4ctrl get drop_reason/table/ingress/nh_table help*

```
Key fields for table nh_table:
	 key name dstAddr
	 key id 1
	 key type ipv4
	 key match type 	 exact
```

This shows the key name "dstAddr" as an exact IPv4 address.
For example to retrieve the entry we created using our key of 10.0.0.2:

*$TC p4ctrl get drop_reason/table/ingress/nh_table dstAddr 10.0.0.2*

Note, we can dump the whole table as such:

*$TC p4ctrl get drop_reason/table/ingress/nh_table*


To cleanup
----------
To clean up you need to run the following script on Terminal 4, where the template was installed and the program was instantiated:

`./drop_reason.purge`
