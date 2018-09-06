# IDPS Code

## Run the IDPS code

You need first to compile the new P4 program, start the network, and use `controller_server.py` 
to install a few rules.

1. In your shell, run:
   ```bash
   cd ~/P4Sec-UFPE/idps
   make
   ```
   This will:
   * compile `idps.p4`,
   * start a Mininet instance with three switches (`s1`, `s2`, `s3`)
     configured in a triangle, each connected to one host (`h1`, `h2`, `h3`), and
   * assign IPs of `10.0.1.1`, `10.0.2.2`, `10.0.3.3` to the respective hosts. The 
     figure below shows this topology.

![topology](topo.png)

2. You should now see a Mininet command prompt. Start a ping between h1 and h2:
   ```bash
   mininet> h1 ping h2
   ```
   Because there are no rules on the switches, you should **not** receive any
   replies yet. You should leave the ping running in this shell.

3. Open another shell and run the IDPS code:
   ```bash
   cd ~/P4Sec-UFPE/idps
   ./controller_server.py
   ```
   This will install the `idps.p4` program on the switches and push the
   the necessary rules to enable communication between hosts. Ping should 
   now work properly.

## Other experiments

1. You should now see a Mininet command prompt. Open two terminals
for `h1` and `h2`, respectively:
   ```bash
   mininet> xterm h1 h2
   ```
2. Each host includes a small Python-based messaging client and
server. In `h2`'s xterm, start the server:
   ```bash
   ./receive.py
   ```
3. In `h1`'s xterm, send a message to `h2`:
   ```bash
   ./send.py 10.0.2.2 "P4Sec is cool"
   ```
   The message must be received.

## Stop the experiments

1. Press `Ctrl-C` to the second shell to stop `controller_server.py`

2. Type `exit` to leave each xterm and the Mininet command line.
   Then, to stop mininet:
   ```bash
   make stop
   ```
   And to delete all pcaps, build files, and logs:
   ```bash
   make clean
   ```

## Auxiliary code (library)

In this solution, you interact with some of the classes and methods in the `p4runtime_lib` 
directory. Here is a summary of each of the files in the directory:
- `helper.py`
  - Contains the `P4InfoHelper` class which is used to parse the `p4info` files.
  - Provides translation methods from entity name to and from ID number.
  - Builds P4 program-dependent sections of P4Runtime table entries.
- `switch.py`
  - Contains the `SwitchConnection` class which grabs the gRPC client stub, and
    establishes connections to the switches.
  - Provides helper methods that construct the P4Runtime protocol buffer messages
    and makes the P4Runtime gRPC service calls.
- `bmv2.py`
  - Contains `Bmv2SwitchConnection` which extends `SwitchConnections` and provides
    the BMv2-specific device payload to load the P4 program.
- `convert.py`
  - Provides convenience methods to encode and decode from friendly strings and
    numbers to the byte strings required for the protocol buffer messages.
  - Used by `helper.py`
