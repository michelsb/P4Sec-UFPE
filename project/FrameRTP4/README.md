# FrameRTP4

## Building Real Time P4 Application

1. Copy/Paste all P4 application files to the `rtp4app` directory
2. Edit the `/rtp4app/config.ini`, indicating the real time processing tables. OBS: such tables must have only ternary match fields. 
3. In your shell, run:
   ```bash
   cd ~/P4Sec-UFPE/project/FrameRTP4/
   make build
   ```
   This will:
   * compile p4 application by using the `p4c-bmv2-ss` command,
   * create a sqlite database,
   * populate the sqllite database with the `rtp4app.json` (compiled file) information data.
   
   
## Running Real Time P4 Application

1. Turn on the TESTBED. You need first to compile the new P4 program, start the network, and use `controller_server.py` 
to install a few rules.
2. In your shell, run:
   ```bash
   cd ~/P4Sec-UFPE/project/FrameRTP4/
   make run
   ```
   This will:
   * start the Real Time P4 Application
   * start an Flask API that enables one to manage the service, by creating and removing table rules)
   
## Clean FrameRTP4 building files

1. In your shell, run:
   ```bash
   cd ~/P4Sec-UFPE/project/FrameRTP4/
   make clean
   ```




