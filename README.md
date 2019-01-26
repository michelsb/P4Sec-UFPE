# P4Sec-UFPE

## Introduction

Repository for software generated within the scope of the P4Sec project, at UFPE.

## Obtaining required software

You will need to build a virtual machine. For this, follow the steps below:

- Install [Vagrant](https://vagrantup.com) and [VirtualBox](https://virtualbox.org)
- `vagrant plugin install vagrant-disksize`
- `git clone -b develop https://github.com/michelsb/P4Sec-UFPE.git`
- `cd P4Sec-UFPE/create-dev-env`
- Create the VM: `vagrant up`
- Accessing the VM: `vagrant ssh`
 
Other auxiliary commands:

- Halt the VM: `vagrant halt` (outside VM) or `sudo shutdown -h now` (inside VM)
- Destroy the VM: `vagrant destroy`



