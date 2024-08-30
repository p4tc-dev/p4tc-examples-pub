# calc

The *calc* program is a toy example of creating an in-band calculator. A client sends  a packet with two numbers and a request for an operation (addition, subtraction, logical and, logical or and logical xor) and the server (a p4 program called calc running in p4node's datapath) does the computation and responds with the result.

The calc header is sent over an Ethernet packet.

```
+-----------------+
|   Calc header   |
+-----------------+
| Ethernet Header |
+-----------------+

The calc header is as follows:

        0                1                  2              3
 +----------------+----------------+----------------+---------------+
 |      P         |       4        |     Version    |     Op        |
 +----------------+----------------+----------------+---------------+
 |                              Operand A                           |
 +----------------+----------------+----------------+---------------+
 |                              Operand B                           |
 +----------------+----------------+----------------+---------------+
 |                              Result                              |
 +----------------+----------------+----------------+---------------+
```

The parser reads the Ethernet Header. If the ethertype is 0x1234 (specifically for the calc) then the calc header is extracted, else the packet is accepted with only the ethernet header. The main control block checks if the calc header has been extracted correctly and if it has then checks the Op field, which specifies the operation. Then based on the operation, the result is stored in the Result field and the packet is sent to the same port from which this packet came from.

XXX: We need to provide credits to the originator of this example

## Setup Requirements

Make sure that the p4node basic container has already been created at this pointas per instructions found in [p4node](https://github.com/p4tc-dev/p4tc-examples-pub.git)). To run the sample described setup here requires 4 terminals, three terminals inside the container and one on the VM side

### Terminal 1 (observation of tc commands on p4node).

Enter the container p4node:

`sudo ip netns exec p4node /bin/bash`

setup path for TC binary

`TC="/usr/sbin/tc"`

setup the path to where the json introspection file can be found..
```
cd /home/vagrant/p4tc-examples-pub/calc/generated
export INTROSPECTION=.
```
run TC monitor:
`$TC mon p4 events`

### Terminal 2 (watch traffic calculator traffic going into p4node0)

This terminal runs on the VM side.
Let's listen to traffic on p4port0. We're going to see packets being sent to the container (by the calc client in terminal 4) and the responses back.

```
DEV=p4port0
sudo tcpdump -n -i $DEV -e
```

### Terminal 3 (instantiating and running the program)

We will run commands to first load the prog and then do any runtime setup.

First enter the container

```
sudo ip netns exec p4node /bin/bash
cd /home/vagrant/p4tc-examples-pub/calc
```

Compile the parser and control blocks programs if you have not already

```
make
```

Make sure you have the introspection path setup and load the calc program

```
export INTROSPECTION=.
TC="/usr/sbin/tc"
cd generated
`./calc.template`
```

now instantiate the prog

```
$TC filter add block 21 ingress protocol all prio 10 p4 pname calc \
action bpf obj calc_parser.o section p4tc/parse \
action bpf obj calc_control_blocks.o section p4tc/main
```

### Terminal 4 (traffic generator)

We're going to run the calc.py program (that is using scapy to send calc headers) on the VM side.

```
cd /home/vagrant/p4tc-examples-pub/calc/generated
sudo ./calc.py
```

Now that the calc.py has started simply use commands:
```
1 + 1
4 - 3
3 & 1
2 | 1
3 ^ 1
```

For each of these computations you run here, the client (*calc.py)* will send requests on *p4port0* (on the VM side) which will then land inside the p4node container's *port0*; the loaded P4 program will then do the arithmetic and loop back the answer to the client which displays it.

To cleanup
----------
To clean up you need to run the following script on Terminal 3, where the template was installed and the program was instantiated:

`./calc.purge`
