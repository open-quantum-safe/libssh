[![CI](https://github.com/open-quantum-safe/libssh/actions/workflows/ci.yml/badge.svg)](https://github.com/open-quantum-safe/libssh/actions/workflows/ci.yml)

OQS-libssh
==================================

[libssh](https://libssh.org/) is an open-source implementation of the Secure Shell protocol. This version of libssh provides support for using "post-quantum" (PQ) cryptographic algorithms. Not to be confused with "quantum cryptography," which is cryptography done on quantum computers, "post-quantum" cryptography (PQC) is algorithms to be used on classical computers which are not vulnerable to the attacks the algorithms in current use (primarily RSA and Elliptic Curve Cryptography) are. See the home page for the Open Quantum Safe (OQS) project at https://openquantumsafe.org/ for further information.

WARNING: These algorithms and implementations are experimental. Standards for post-quantum cryptographic algorithms are still under development. Included at this time are implementations of algorithms from Round 3 of the NIST's Post-Quantum Cryptography standardization process. While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in the OQS project, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project. Accordingly, although "pure-PQ" options are provided, we recommend only enabling "hybrid" options, which combine time-tested classical algorithms with new PQ algorithms. This will ensure the solution is at least no less secure than existing traditional cryptography.

- [Overview](#overview)
- [Build Instructions for libssh](#build-instructions)
- [Build Instructions for OQS-OpenSSH](#build-instructions-for-oqs-openssh)
- [Key Exchange Algorithms](#key-exchange-algorithms)
- [Digital Signature Algorithms](#digital-signature-algorithms)
- [Known Issues](#known-issues)
- [Contributing](#contributing)
- [License](#license)
- [Team](#team)
- [Acknowledgements](#acknowledgements)

## Overview

This implementation is designed to interoperate with the OQS project's fork of OpenSSH v8, available at https://github.com/open-quantum-safe/openssh. As the protocol is not yet standardized and may change without any allowance for backwards-compatibility, future changes to OQS-OpenSSH may break interoperability until this library can be updated.

The build instructions here always use the latest development versions of liboqs and OQS-OpenSSH, but it is possible changes in those dependencies may cause libssh's build to break, before we have a chance to update it. If that happens, the following commit IDs are known to work with this build, and can manually be snapped to by providing them to `git checkout` after cloning the repositories in the instructions below.

* liboqs: commit ID a39d08e00a852adc191112090ece924c874caaac "liboqs 0.7.1"
* OQS-OpenSSH: commit ID e9b0f6f8896039824f78a43623cd14b67f24e2ce "Use mpint representation for shared_secret when deriving keys in pure-PQ key exchange, and some other bug fixes; fixes #119 (#120)".

This implementation tracks libssh's `master` branch that contains the current development version. At this time, this library is based on libssh's commit ID 4975487c18090e24ff97208022a605a15351e773 "config: Include files with relative paths", which was committed on 2022-02-10.

This support can only be built if OpenSSL is used as the cryptographic library for libssh, due to liboqs's reliance on OpenSSL for some symmetric cryptographic primitives. libgcrypt and mbedTLS are not supported.

## Build Instructions

1. Clone the liboqs repository's main branch, and then snap to the particular commit above, which is the latest version of liboqs known to work with libssh. Newer versions of liboqs may work, but there is no guarantee. Do this outside of the libssh repository clone.

```
    git clone --branch main --single-branch --depth 1 https://github.com/open-quantum-safe/liboqs.git
```

2. Install necessary dependencies. In particular, you will need CMake, Ninja, gcc, and libssl-dev to build. On Ubuntu:

```
    sudo apt install cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz
```

If you want to build client as well as server tests for libssh (-DCLIENT_TESTING=ON) below in step 6, install these additional dependencies. On Ubuntu:

```
    sudo apt install libcmocka-dev libcmocka0 libsocket-wrapper libnss-wrapper libuid-wrapper libpam-wrapper
```
 
3. Choose an appropriate installation location for OQS's libraries and include files. Example choices are `/usr/local` or `/usr/local/oqs` for a system-wide installation, or `${HOME}/oqs` or `${HOME}/build/oqs` for a user-local installation. This can be anywhere, but in the instructions below we refer to it as `${OQS_ROOT_DIR}`. 

4. Build and install liboqs. Change directory into the repository for liboqs cloned above, and execute these steps:

```
  mkdir build && cd build
  cmake -GNinja -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=${OQS_ROOT_DIR} ..
  ninja
  ninja install
```
 
5. OPTIONAL: Build OQS-OpenSSH [using the instructions below](#build-instructions-for-oqs-openssh). This is **required** to run tests, which use OpenSSH as the remote client or server. To run any tests, including the pkd_hello test suite, you MUST build OQS-OpenSSH, and add the path to the ssh binary it creates to your PATH environment variable before any official version of OpenSSH, so that libssh's CMake detects it and not the official version. 

   Failing to do this step BEFORE running CMake in step 6 will cause tests to fail en masse, as it will not call the PQ-enabled OpenSSH client.
  
6. Configure and build libssh with the post-quantum cryptography turned on. We follow the regular instructions for libssh (see `INSTALL`), but we add two new configuration directives for cmake: `WITH_POST_QUANTUM_CRYPTO` and `OQS_ROOT_DIR`. Set `WITH_POST_QUANTUM_CRYPTO` to `ON` to enable the algorithms, and set `OQS_ROOT_DIR` to be the value of `${OQS_ROOT_DIR}` you chose above. Without the `WITH_POST_QUANTUM_CRYPTO` setting, PQC is not included. Change directory back into the repository for libssh, and execute these steps:

```
  mkdir build && cd build
  cmake -DUNIT_TESTING=ON -DWITH_SERVER=ON -DSERVER_TESTING=ON -DCMAKE_BUILD_TYPE=Debug -DWITH_POST_QUANTUM_CRYPTO=ON -DOQS_ROOT_DIR=${OQS_ROOT_DIR} ..
  make -j
```

If you want to build the tests for libssh in client mode as well as server mode, add `-DCLIENT_TESTING=ON` to the `cmake` command line above. See Known Issues at the bottom of this document concerning the client tests. 

The above steps will create the `build` directory underneath the libssh repository, but you can place it anywhere. If you place it elsewhere, replace the `..` argument at the end of the call to cmake with the full path to the libssh repository.

### Preserving client and server authentication keys for runs of the `pkd_hello` suite

By default, the `pkd_hello` test suite deletes all the authentication keys used by libssh as a server and OpenSSH as a client after the test run is complete. Because `WITH_POST_QUANTUM_CRYPTO=ON` adds many more key types, there can be a delay of up to a couple of minutes before test runs while keys are generated. pkd_hello now has a command option `-p` for "preserve," which will not delete these keys. If the key files are then present when pkd_hello runs, those keys will be reused. While we recommend the default behavior and always generate fresh keys for CI or other automated test runs, developers may find it convenient to preserve keys to speed up testing during development.


## Build instructions for OQS-OpenSSH

libssh interoperates with the Open Quantum Safe project's [fork of OpenSSH](https://github.com/open-quantum-safe/openssh) that adds post-quantum cryptography. If you are only building the libssh library itself, building OQS-OpenSSH is not required. However, building any of libssh's test code requires building OQS-OpenSSH in step 5 above, as the test code calls OpenSSH as part of its operation. When running libssh's server tests, OpenSSH is used as the client. Similarly, when running libssh's client tests, OpenSSH is used as the server.

The OQS version of OpenSSH can be used by building it and adding an entry to your PATH that precedes where the system-installed versions of OpenSSH are located. These will also be used by other clients that rely on OpenSSH, such as git. See https://github.com/open-quantum-safe/openssh/ for more information on using OQS-OpenSSH.

These instructions assume you have completed the build above; in particular, that liboqs is built and copied to `${OQS_ROOT_DIR}`.

1. Clone the openssh repository `OQS-v7.9` branch, and then snap to the particular commit above, which is the version known to interoperate with libssh. Newer versions of OQS-OpenSSH may work, but there is no guarantee. Do this outside of the libssh or liboqs repository clones.

```
  git clone --branch OQS-v8 --single-branch --depth 1 https://github.com/open-quantum-safe/openssh.git
```
  
2. Install necessary dependencies. In particular, beyond what libssh and liboqs require, OpenSSH requires autoconf, automake, libtool, and zlib1g-dev. On Ubuntu:

```
  sudo apt install autoconf automake cmake gcc libtool libssl-dev make ninja-build zlib1g-dev
```
  
3. Choose an appropriate installation location for OQS's version of OpenSSH. Example choices are `/usr/local` or `/usr/local/openssh` for a system-wide installation, or `${HOME}/openssh` or `${HOME}/build/openssh` for a user-local installation. This can be anywhere, but in the instructions below we refer to it as `${OPENSSH_INSTALL}`. We strongly discourage installing this over top of your existing OpenSSH installation.

4. Configure and build OQS-OpenSSH.

```
  autoreconf
  ./configure --with-libs=-lm --prefix=${OPENSSH_INSTALL} --sysconfdir=${OPENSSH_INSTALL} --with-liboqs-dir=${OQS_ROOT_DIR}
  make -j
  make install
```
  
5. Prefix your installation path to your `PATH` to default to those binaries. This setting will only persist for your current shell session; add the appropriate commands to your shell dot files (such as `.bashrc`) for a permanent change. For bash:

```
  PATH=${OPENSSH_INSTALL}/bin:$PATH
```

## Key Exchange Algorithms

The following key exchange algorithm strings are the hybrid algorithms we recommend using, that combine an established classical algorithm with a post-quantum algorithm. They can be provided to the "-o KexAlgorithms" option to both ssh and sshd. The "ecdh-nistp384-oqsdefault-sha384@openquantumsafe.org" option chooses a suitable default, but specific PQ algorithms can be chosen. See the OQS home page for information on the algorithms.

<!--- OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_KEXS_START -->
* ecdh-nistp256-frodokem-640-aes-sha256@openquantumsafe.org
* ecdh-nistp384-frodokem-976-aes-sha384@openquantumsafe.org
* ecdh-nistp521-frodokem-1344-aes-sha512@openquantumsafe.org
* ecdh-nistp256-frodokem-640-shake-sha256@openquantumsafe.org
* ecdh-nistp384-frodokem-976-shake-sha384@openquantumsafe.org
* ecdh-nistp521-frodokem-1344-shake-sha512@openquantumsafe.org
* ecdh-nistp256-saber-lightsaber-sha256@openquantumsafe.org
* ecdh-nistp384-saber-saber-sha384@openquantumsafe.org
* ecdh-nistp521-saber-firesaber-sha512@openquantumsafe.org
* ecdh-nistp256-kyber-512-sha256@openquantumsafe.org
* ecdh-nistp384-kyber-768-sha384@openquantumsafe.org
* ecdh-nistp521-kyber-1024-sha512@openquantumsafe.org
* ecdh-nistp256-kyber-512-90s-sha256@openquantumsafe.org
* ecdh-nistp384-kyber-768-90s-sha384@openquantumsafe.org
* ecdh-nistp521-kyber-1024-90s-sha512@openquantumsafe.org
* ecdh-nistp256-bike-l1-sha512@openquantumsafe.org
* ecdh-nistp384-bike-l3-sha512@openquantumsafe.org
* ecdh-nistp256-ntru-hps2048509-sha512@openquantumsafe.org
* ecdh-nistp384-ntru-hps2048677-sha512@openquantumsafe.org
* ecdh-nistp521-ntru-hps4096821-sha512@openquantumsafe.org
* ecdh-nistp521-ntru-hps40961229-sha512@openquantumsafe.org
* ecdh-nistp384-ntru-hrss701-sha512@openquantumsafe.org
* ecdh-nistp521-ntru-hrss1373-sha512@openquantumsafe.org
* ecdh-nistp256-classic-mceliece-348864-sha256@openquantumsafe.org
* ecdh-nistp256-classic-mceliece-348864f-sha256@openquantumsafe.org
* ecdh-nistp384-classic-mceliece-460896-sha512@openquantumsafe.org
* ecdh-nistp384-classic-mceliece-460896f-sha512@openquantumsafe.org
* ecdh-nistp521-classic-mceliece-6688128-sha512@openquantumsafe.org
* ecdh-nistp521-classic-mceliece-6688128f-sha512@openquantumsafe.org
* ecdh-nistp521-classic-mceliece-6960119-sha512@openquantumsafe.org
* ecdh-nistp521-classic-mceliece-6960119f-sha512@openquantumsafe.org
* ecdh-nistp521-classic-mceliece-8192128-sha512@openquantumsafe.org
* ecdh-nistp521-classic-mceliece-8192128f-sha512@openquantumsafe.org
* ecdh-nistp256-hqc-128-sha256@openquantumsafe.org
* ecdh-nistp384-hqc-192-sha384@openquantumsafe.org
* ecdh-nistp521-hqc-256-sha512@openquantumsafe.org
* ecdh-nistp256-ntruprime-ntrulpr653-sha256@openquantumsafe.org
* ecdh-nistp256-ntruprime-sntrup653-sha256@openquantumsafe.org
* ecdh-nistp384-ntruprime-ntrulpr761-sha384@openquantumsafe.org
* ecdh-nistp384-ntruprime-sntrup761-sha384@openquantumsafe.org
* ecdh-nistp384-ntruprime-ntrulpr857-sha384@openquantumsafe.org
* ecdh-nistp384-ntruprime-sntrup857-sha384@openquantumsafe.org
* ecdh-nistp521-ntruprime-ntrulpr1277-sha512@openquantumsafe.org
* ecdh-nistp521-ntruprime-sntrup1277-sha512@openquantumsafe.org
<!--- OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_KEXS_END -->

The following key exchange algorithm strings are pure-PQ algorithms. They should only be used experimentally.

<!--- OQS_TEMPLATE_FRAGMENT_LIST_PQ_KEXS_START -->
* frodokem-640-aes-sha256@openquantumsafe.org
* frodokem-976-aes-sha384@openquantumsafe.org
* frodokem-1344-aes-sha512@openquantumsafe.org
* frodokem-640-shake-sha256@openquantumsafe.org
* frodokem-976-shake-sha384@openquantumsafe.org
* frodokem-1344-shake-sha512@openquantumsafe.org
* saber-lightsaber-sha256@openquantumsafe.org
* saber-saber-sha384@openquantumsafe.org
* saber-firesaber-sha512@openquantumsafe.org
* kyber-512-sha256@openquantumsafe.org
* kyber-768-sha384@openquantumsafe.org
* kyber-1024-sha512@openquantumsafe.org
* kyber-512-90s-sha256@openquantumsafe.org
* kyber-768-90s-sha384@openquantumsafe.org
* kyber-1024-90s-sha512@openquantumsafe.org
* bike-l1-sha512@openquantumsafe.org
* bike-l3-sha512@openquantumsafe.org
* ntru-hps2048509-sha512@openquantumsafe.org
* ntru-hps2048677-sha512@openquantumsafe.org
* ntru-hps4096821-sha512@openquantumsafe.org
* ntru-hps40961229-sha512@openquantumsafe.org
* ntru-hrss701-sha512@openquantumsafe.org
* ntru-hrss1373-sha512@openquantumsafe.org
* classic-mceliece-348864-sha256@openquantumsafe.org
* classic-mceliece-348864f-sha256@openquantumsafe.org
* classic-mceliece-460896-sha512@openquantumsafe.org
* classic-mceliece-460896f-sha512@openquantumsafe.org
* classic-mceliece-6688128-sha512@openquantumsafe.org
* classic-mceliece-6688128f-sha512@openquantumsafe.org
* classic-mceliece-6960119-sha512@openquantumsafe.org
* classic-mceliece-6960119f-sha512@openquantumsafe.org
* classic-mceliece-8192128-sha512@openquantumsafe.org
* classic-mceliece-8192128f-sha512@openquantumsafe.org
* hqc-128-sha256@openquantumsafe.org
* hqc-192-sha384@openquantumsafe.org
* hqc-256-sha512@openquantumsafe.org
* ntruprime-ntrulpr653-sha256@openquantumsafe.org
* ntruprime-sntrup653-sha256@openquantumsafe.org
* ntruprime-ntrulpr761-sha384@openquantumsafe.org
* ntruprime-sntrup761-sha384@openquantumsafe.org
* ntruprime-ntrulpr857-sha384@openquantumsafe.org
* ntruprime-sntrup857-sha384@openquantumsafe.org
* ntruprime-ntrulpr1277-sha512@openquantumsafe.org
* ntruprime-sntrup1277-sha512@openquantumsafe.org
<!--- OQS_TEMPLATE_FRAGMENT_LIST_PQ_KEXS_END -->

## Digital Signature Algorithms

Digital signature algorithms are used in SSH for host key authentication and user key authentication. These strings can be used with the -t argument to ssh-keygen from OQS-OpenSSH to generate a particular type of user authentication key pair. Currently, libssh as a server can only load one OQS-provided host key, in addition to the classical key types already supported, so presently it is not possible to offer multiple PQ/hybrid host keys. There is no such limitation on the number of user authentication keys or key types that can be authorized.

The following digital signature algorithm strings are the hybrid algorithms we recommend using, that combine established classical algorithms with a post-quantum algorithm. Algorithms that are built by default are marked with an asterisk. The others are excluded by default due to long run times, but they can be enabled by editing `oqs-template/generate.yml`, adding the line `enable: true` to the algorithm's section,   running `python3 oqs-template/generate.py` to regenerate templated code, and then building as usual.

<!--- OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_SIGS_START -->
* ssh-rsa3072-falcon512\*
* ssh-ecdsa-nistp256-falcon512\*
* ssh-ecdsa-nistp521-falcon1024\*
* ssh-rsa3072-dilithium2
* ssh-ecdsa-nistp256-dilithium2
* ssh-ecdsa-nistp384-dilithium3\*
* ssh-ecdsa-nistp521-dilithium5
* ssh-rsa3072-dilithium2aes\*
* ssh-ecdsa-nistp256-dilithium2aes\*
* ssh-ecdsa-nistp384-dilithium3aes
* ssh-ecdsa-nistp521-dilithium5aes\*
* ssh-rsa3072-picnicL1FS
* ssh-ecdsa-nistp256-picnicL1FS
* ssh-rsa3072-picnicL1UR
* ssh-ecdsa-nistp256-picnicL1UR
* ssh-rsa3072-picnicL1full\*
* ssh-ecdsa-nistp256-picnicL1full\*
* ssh-ecdsa-nistp384-picnicL3FS\*
* ssh-ecdsa-nistp384-picnicL3UR
* ssh-ecdsa-nistp384-picnicL3full
* ssh-ecdsa-nistp521-picnicL5FS
* ssh-ecdsa-nistp521-picnicL5UR
* ssh-ecdsa-nistp521-picnicL5full
* ssh-ecdsa-nistp384-rainbowIIIclassic
* ssh-ecdsa-nistp384-rainbowIIIcircumzenithal
* ssh-ecdsa-nistp384-rainbowIIIcompressed
* ssh-ecdsa-nistp521-rainbowVclassic
* ssh-ecdsa-nistp521-rainbowVcircumzenithal
* ssh-ecdsa-nistp521-rainbowVcompressed
* ssh-rsa3072-sphincsharaka128frobust
* ssh-ecdsa-nistp256-sphincsharaka128frobust
* ssh-rsa3072-sphincsharaka128fsimple\*
* ssh-ecdsa-nistp256-sphincsharaka128fsimple\*
* ssh-rsa3072-sphincsharaka128srobust
* ssh-ecdsa-nistp256-sphincsharaka128srobust
* ssh-rsa3072-sphincsharaka128ssimple
* ssh-ecdsa-nistp256-sphincsharaka128ssimple
* ssh-rsa3072-sphincssha256128frobust
* ssh-ecdsa-nistp256-sphincssha256128frobust
* ssh-rsa3072-sphincssha256128srobust
* ssh-ecdsa-nistp256-sphincssha256128srobust
* ssh-rsa3072-sphincssha256128fsimple
* ssh-ecdsa-nistp256-sphincssha256128fsimple
* ssh-rsa3072-sphincssha256128ssimple
* ssh-ecdsa-nistp256-sphincssha256128ssimple
* ssh-rsa3072-sphincsshake256128frobust
* ssh-ecdsa-nistp256-sphincsshake256128frobust
* ssh-rsa3072-sphincsshake256128srobust
* ssh-ecdsa-nistp256-sphincsshake256128srobust
* ssh-rsa3072-sphincsshake256128fsimple
* ssh-ecdsa-nistp256-sphincsshake256128fsimple
* ssh-rsa3072-sphincsshake256128ssimple
* ssh-ecdsa-nistp256-sphincsshake256128ssimple
* ssh-ecdsa-nistp384-sphincsharaka192frobust\*
* ssh-ecdsa-nistp384-sphincsharaka192srobust
* ssh-ecdsa-nistp384-sphincsharaka192fsimple
* ssh-ecdsa-nistp384-sphincsharaka192ssimple
* ssh-ecdsa-nistp384-sphincssha256192frobust
* ssh-ecdsa-nistp384-sphincssha256192srobust
* ssh-ecdsa-nistp384-sphincssha256192fsimple
* ssh-ecdsa-nistp384-sphincssha256192ssimple
* ssh-ecdsa-nistp384-sphincsshake256192frobust
* ssh-ecdsa-nistp384-sphincsshake256192srobust
* ssh-ecdsa-nistp384-sphincsshake256192fsimple
* ssh-ecdsa-nistp384-sphincsshake256192ssimple
* ssh-ecdsa-nistp521-sphincsharaka256frobust
* ssh-ecdsa-nistp521-sphincsharaka256srobust
* ssh-ecdsa-nistp521-sphincsharaka256fsimple
* ssh-ecdsa-nistp521-sphincsharaka256ssimple
* ssh-ecdsa-nistp521-sphincssha256256frobust
* ssh-ecdsa-nistp521-sphincssha256256srobust
* ssh-ecdsa-nistp521-sphincssha256256fsimple
* ssh-ecdsa-nistp521-sphincssha256256ssimple
* ssh-ecdsa-nistp521-sphincsshake256256frobust
* ssh-ecdsa-nistp521-sphincsshake256256srobust
* ssh-ecdsa-nistp521-sphincsshake256256fsimple
* ssh-ecdsa-nistp521-sphincsshake256256ssimple
<!--- OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_SIGS_END -->

The following digital signature algorithm strings are pure-PQ algorithms. They should only be used experimentally.

<!--- OQS_TEMPLATE_FRAGMENT_LIST_PQ_SIGS_START -->
* ssh-falcon512\*
* ssh-falcon1024\*
* ssh-dilithium2
* ssh-dilithium3\*
* ssh-dilithium5
* ssh-dilithium2aes\*
* ssh-dilithium3aes
* ssh-dilithium5aes\*
* ssh-picnicl1fs
* ssh-picnicl1ur
* ssh-picnicl1full\*
* ssh-picnicl3fs\*
* ssh-picnicl3ur
* ssh-picnicl3full
* ssh-picnicl5fs
* ssh-picnicl5ur
* ssh-picnicl5full
* ssh-rainbowiiiclassic
* ssh-rainbowiiicircumzenithal
* ssh-rainbowiiicompressed
* ssh-rainbowvclassic
* ssh-rainbowvcircumzenithal
* ssh-rainbowvcompressed
* ssh-sphincsharaka128frobust
* ssh-sphincsharaka128fsimple\*
* ssh-sphincsharaka128srobust
* ssh-sphincsharaka128ssimple
* ssh-sphincssha256128frobust
* ssh-sphincssha256128srobust
* ssh-sphincssha256128fsimple
* ssh-sphincssha256128ssimple
* ssh-sphincsshake256128frobust
* ssh-sphincsshake256128srobust
* ssh-sphincsshake256128fsimple
* ssh-sphincsshake256128ssimple
* ssh-sphincsharaka192frobust\*
* ssh-sphincsharaka192srobust
* ssh-sphincsharaka192fsimple
* ssh-sphincsharaka192ssimple
* ssh-sphincssha256192frobust
* ssh-sphincssha256192srobust
* ssh-sphincssha256192fsimple
* ssh-sphincssha256192ssimple
* ssh-sphincsshake256192frobust
* ssh-sphincsshake256192srobust
* ssh-sphincsshake256192fsimple
* ssh-sphincsshake256192ssimple
* ssh-sphincsharaka256frobust
* ssh-sphincsharaka256srobust
* ssh-sphincsharaka256fsimple
* ssh-sphincsharaka256ssimple
* ssh-sphincssha256256frobust
* ssh-sphincssha256256srobust
* ssh-sphincssha256256fsimple
* ssh-sphincssha256256ssimple
* ssh-sphincsshake256256frobust
* ssh-sphincsshake256256srobust
* ssh-sphincsshake256256fsimple
* ssh-sphincsshake256256ssimple
<!--- OQS_TEMPLATE_FRAGMENT_LIST_PQ_SIGS_END -->

## Known Issues

1. When running as a server, currently only one host key of an PQ/hybrid type can be loaded alongside the usual classical key types, to be presented to clients.

2. The larger key sizes and payloads required of PQ/hybrid algorithms causes individual messages to be much larger, and this can cause problems with the socket_wrapper library used in test code, causing parts of messages to be lost. These problems have not yet been observed when running without socket_wrapper and using real network sockets. This can result in client tests failing, but so far this appears to be a problem with the test libraries, and libssh operates correctly in client mode.

## Contributing

Contributions are gratefully welcomed. Contributions are accepted via pull request.

## License

This fork is released under the same license(s) as libssh. More information can be found in the [COPYING](COPYING) file.

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to this fork of libssh include:

- Kevin Kane (Microsoft Research)
- Christian Paquin (Microsoft Research)

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Canadian Centre for Cyber Security.
We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.