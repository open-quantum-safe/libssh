OQS-libssh snapshot 2022-01
===========================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-libssh** is an integration of quantum-resistant algorithm from liboqs into (a fork of) libssh.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is the 2022-01 snapshot release of OQS-libssh, released on January 24, 2022. This release is intended to be used with liboqs version 0.7.1.

What's New
----------

This is the first snapshot release of the OQS fork of libssh.  It is based on libssh version 0.8.9.  It supports post-quantum and hybrid key exchange and authentication in the SSH protocol.
