FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
        cmake \
        git \
        gcc \
        g++ \
        ninja-build \
        libssl-dev \
        python3-pytest \
        python3-pytest-xdist \
        unzip \
        xsltproc \
        doxygen \
        graphviz \
        libcmocka-dev \
        libcmocka0 \
        libsocket-wrapper \
        libnss-wrapper \
        libuid-wrapper \
        libpam-wrapper \
        autoconf \
        automake \
        libtool \
        libssl-dev \
        zlib1g-dev \
        libpam0g-dev

WORKDIR /opt

RUN git clone -b OQS-master https://github.com/open-quantum-safe/libssh.git libssh

WORKDIR /opt/libssh

RUN git clone -b main https://github.com/open-quantum-safe/liboqs.git oqs-scripts/tmp/liboqs
RUN git clone -b OQS-v8 https://github.com/open-quantum-safe/openssh.git oqs-scripts/tmp/openssh

RUN oqs-scripts/build_liboqs.sh
RUN oqs-scripts/build_openssh.sh
RUN oqs-scripts/build_libssh.sh

RUN groupadd sshd
RUN useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd
