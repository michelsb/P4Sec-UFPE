# P4Sec-UFPE

## Introduction

Repository for software generated within the scope of the P4Sec project, at UFPE.

## Obtaining required software

You will need to build a virtual machine. For this, follow the steps below:

- Install [Vagrant](https://vagrantup.com) and [VirtualBox](https://virtualbox.org)
- `git clone -b develop https://github.com/michelsb/P4Sec-UFPE.git`
- `cd create-dev-env`
- Create the VM: `vagrant up`
- Access the VM: `vagrant ssh`
- Download the repository inside the VM: 
   ```bash
   cd ~
   git clone -b develop https://github.com/michelsb/P4Sec-UFPE.git
   ```
 
Other auxiliary commands:

- Halt the VM: `vagrant halt` (outside VM) or `sudo shutdown -h now` (inside VM)
- Destroy the VM: `vagrant destroy`



