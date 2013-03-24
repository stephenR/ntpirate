ntpirate
========

Proof of concept for an NTP Autokey vulnerability

Requirements
============

* OpenSSL
* libpcap

Usage
=====

This sample exploit assumes the following network topology:
* Your machine is a man-in-the-middle between an ntp client (alice) and server (bob)
* The packets from alice and bob arrive on the same interface $i, but are not forwarded to each other
* E.g. if you have interface $i0 for alice and $i1 for bob, create a bridge interface $i and use ebtables to drop ntp packets

ntpirate will listen on a given device for ntp packets using libpcap and forward/spoof them as needed.

Just start it with ./ntpirate $i [time_offset [rsa_key_file]]

If no key_file is given, one will be created on startup.

