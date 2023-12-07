# Flowtracker IPv6

The *flowtracker\_ipv6* program tracks any TCP flows ingressing into port0 or port1.

After parsing a TCP/IPv4 packet, *flowtracker\_ipv6* constructs a 136b key based on the 5 tuples: {*IPv4 src/dst IP, src/dst tcp port and protocol=tcp*}. The key is used to lookup the table *ct_tcp_table*. If there is a table lookup <u>miss</u> then a new entry is created using the "add-on-miss" *ct_flow_miss* action and the flows 5 tuple is inserted into the table *ct_tcp_table*. If there is a <u>hit</u> on the entry, then entry's idle timer is refreshed. The entry is eventually deleted if becomes is idle for a period equal to the default aging timer (30 seconds).

The control plane is notified whenever a new entry is created (by the datapath) or deleted (by the timer or user/ctrl plane). Note: To change this timeout period you will have to set the aging timeout in the template creation. The aging parameter is specified in ms, so for example to change it to 10s, edit the template as follows from:
*keysz 136 nummasks 8 tentries 2048 permissions 0x3DE4 \*
to:
*keysz 136 nummasks 8 tentries 2048 permissions 0x3DE4 aging 10000 \*

## Setup Requirements

Make sure that the p4node basic container has already been created at this point. To run the sample described setup here requires 3 terminals, two terminals inside the container and one on the VM side

## Counter module

For the counter to work, you'll need to copy its module from the directory net/sched/p4tc/externs/ to the flowtracker\_ipv6 directory.
You'll find it under the following path: net/sched/p4tc/externs/ext\_Counter.ko
In this specific example, the counter will count packets and bytes

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node:

`sudo ip netns exec p4node /bin/bash`

setup path for TC binary

`TC="/usr/sbin/tc"`

setup the path to where the json introspection file can be found..

```
cd /home/vagrant/p4tc-examples-pub//stateful-progs/flowtracker\_ipv6/generated
export INTROSPECTION=.
```

run TC monitor:

`$TC mon`

### Terminal 2

we will run commands to first instatiate the prog and then do any runtime setup

First enter the container and make sure you have the introspection path setup

```
sudo ip netns exec p4node /bin/bash
cd /home/vagrant/p4tc-examples-pub//stateful-progs/flowtracker\_ipv6/generated
export INTROSPECTION=.
TC="/usr/sbin/tc"
```

Run the template script to prescribe the program - watch for tc mon(terminal 1) to see things happening

`./flowtracker\_ipv6.template`

Compile the parser and control blocks ebpf programs if you havent already

`make`

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname flowtracker\_ipv6 \
action bpf obj flowtracker_parser.o section classifier/tc-parse \
action bpf obj flowtracker_control_blocks.o section classifier/tc-ingress
```

let's run the nc server inside the container... Note this step is not necessary unless you want to keep the flow alive on the P4 side.

`nc -l -p 1234 -s  10.0.0.2`

### Terminal 3

Outside on the VM from, used for sending a packet to container..

`nc 10.0.0.2 1234`

You should immediately see on on <u>terminal 1</u> an event advertising that a table entry has been created (as illustrated below).

```
 created pipeline:  flowtracker\_ipv6(id 1)
  table: Main/ct_tcp_table(id 1)entry priority 64000[permissions -RUD-PS-R--X--]
     entry key
      input_port id:1 size:32b type:dev exact fieldval  port0
      srcAddr id:2 size:32b type:ipv4 exact fieldval  10.0.0.1/32
      dstAddr id:3 size:32b type:ipv4 exact fieldval  10.0.0.2/32
      hdr.ipv4.protocol id:4 size:8b type:bit8 exact fieldval  6
      src_port id:5 size:16b type:be16 exact fieldval  45506
      dstPort id:6 size:16b type:be16 exact fieldval  1234
     created by: kernel (id 1)
     dynamic true
     table aging 30000
```

Type a few characters followed by CR key if you want to keep this flow alive..

And if you wait for 30 seconds without typing anything on the nc window (terminal 3) you will see the entry getting expired by the kernel idle timer, as such:

```
 deleted pipeline:  flowtracker\_ipv6(id 1)
  table: Main/ct_tcp_table(id 1)entry priority 64000[permissions -RUD-PS-R--X--]
     entry key
      input_port id:1 size:32b type:dev exact fieldval  port0
      srcAddr id:2 size:32b type:ipv4 exact fieldval  10.0.0.1/32
      dstAddr id:3 size:32b type:ipv4 exact fieldval  10.0.0.2/32
      hdr.ipv4.protocol id:4 size:8b type:bit8 exact fieldval  6
      src_port id:5 size:16b type:be16 exact fieldval  45506
      dstPort id:6 size:16b type:be16 exact fieldval  1234
     created by: kernel (id 1)
     deleted by: timer (id 3)
     dynamic true
     table aging 30000
     created 30 sec    used 30 sec
```

Other commands
---------------
to dump the table entries:
`tc p4ctrl get flowtracker\_ipv6/table/Main/ct\_tcp\_table`

Dump in json format:
`tc -j p4ctrl get flowtracker\_ipv6/table/Main/ct\_tcp\_table`

To cleanup
----------
To clean up you need to run the following script on Terminal 2, where the template was installed and the program was instantiated:
`./flowtracker\_ipv6.purge`
