#!/bin/bash

# Print commands and exit on errors
set -xe

apt-get update

KERNEL=$(uname -r)
DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade
apt-get install -y --no-install-recommends \
  autoconf \
  automake \
  bison \
  build-essential \
  ca-certificates \
  cmake \
  cpp \
  curl \
  emacs24 \
  flex \
  git \
  libboost-dev \
  libboost-filesystem-dev \
  libboost-iostreams1.58-dev \
  libboost-program-options-dev \
  libboost-system-dev \
  libboost-test-dev \
  libboost-thread-dev \
  libc6-dev \
  libevent-dev \
  libffi-dev \
  libfl-dev \
  libgc-dev \
  libgc1c2 \
  libgflags-dev \
  libgmp-dev \
  libgmp10 \
  libgmpxx4ldbl \
  libjudy-dev \
  libpcap-dev \
  libreadline6 \
  libreadline6-dev \
  libssl-dev \
  libtool \
  linux-headers-$KERNEL\
  make \
  mktemp \
  pkg-config \
  python \
  python-dev \
  python-ipaddr \
  python-pip \
  python-scapy \
  python-setuptools \
  tcpdump \
  unzip \
  vim \
  wget \
  xcscope-el \
  xterm

pip install sqlalchemy
pip install flask
pip install pandas

if [ -x "$(command -v p4c-bm2-ss)" ]; then
  echo 'P4C is already installed.' >&2
  exit 1
fi

P4C_COMMIT="48a57a6ae4f96961b74bd13f6bdeac5add7bb815"
NUM_CORES=`grep -c ^processor /proc/cpuinfo`

# P4C
git clone https://github.com/p4lang/p4c
cd p4c
git checkout ${P4C_COMMIT}
git submodule update --init --recursive
mkdir -p build
cd build
cmake ..
make -j${NUM_CORES}
make -j${NUM_CORES} check
sudo make install
sudo ldconfig
cd ..
cd ..
  