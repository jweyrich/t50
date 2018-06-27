```
      __________ ________  _____
     |__    ___/|   ____/ /  _  \ the fastest packet injector.
       |    |   |____  \ /  /_\  \
       |    |   /       \\  \_/   \
       |____|  /________/\\_______/
```

T50 (f.k.a. F22 Raptor) is a tool designed to perform "Stress Testing". The concept started on 2001, right after release 'nb-isakmp.c', and the main goal was:

* Having a tool to perform TCP/IP protocol fuzzer,  covering common regular protocols, such as: ICMP, TCP and UDP.

Things have changed, and the T50 became a good unique resource capable to perform "Stress Testing". And, after checking the "/usr/include/linux", some protocols were chosen to be part of its coverage: 

* ICMP   - Internet Control Message Protocol
* IGMP   - Internet Group Management Protocol
* TCP    - Transmission Control Protocol
* UDP    - User Datagram Protocol

Why "Stress Testing"? Well, because when people are designing a new network infra-structure (eg. Datacenter serving to Cloud Computing) they think about:

* High-Availability
* Load Balancing
* Backup Sites (Cold Sites, Hot Sites, and Warm Sites)
* Disaster Recovery
* Data Redundancy
* Service Level Agreements
* Etc...

But almost nobody thinks about "Stress Testing", or even performs any test to check how the networks infra-structure behaves under stress, under overload, and under attack. Even during a Penetration Test, people prefer not running any kind of Denial-of-Service testing. Even worse, those people are missing one of the three key concepts of security that are common to risk management:

* Confidentiality
* Integrity
* AVAILABILITY

T50 was designed to perform “Stress Testing” on a variety of infra-structure network devices (Version 2.45), using widely implemented protocols, and after some requests it was was re-designed to extend the tests (as of Version 5.3), covering some regular protocols (ICMP, TCP and UDP), some infra-structure specific protocols (GRE, IPSec and RSVP), and some routing protocols (RIP, EIGRP and OSPF).

T50 is a powerful and unique packet injector tool, which is capable to:

1. Send sequentially the following fifteen (15) protocols:
	* ICMP   - Internet Control Message Protocol
	* IGMPv1 - Internet Group Management Protocol v1
	* IGMPv3 - Internet Group Management Protocol v3
	* TCP    - Transmission Control Protocol
	* EGP    - Exterior Gateway Protocol
	* UDP    - User Datagram Protocol
	* RIPv1  - Routing Information Protocol v1
	* RIPv2  - Routing Information Protocol v2
	* DCCP   - Datagram Congestion Control Protocol
	* RSVP   - Resource ReSerVation Protocol
	* GRE    - Generic Routing Encapsulation
	* IPSec  - Internet Protocol Security (AH/ESP)
	* EIGRP  - Enhanced Interior Gateway Routing Protocol
	* OSPF   - Open Shortest Path First

2. It is the only tool capable to encapsulate the protocols  (listed above) within Generic Routing Encapsulation (GRE).

3. Send an (quite) incredible amount of packets per second, making it a "second to none" tool:
	* More than 1,000,000 pps of SYN Flood  (+50% of the network uplink) in a 1000BASE-T Network (Gigabit Ethernet).
	* More than 120,000 pps of SYN Flood  (+60% of the network uplink) in a 100BASE-TX Network (Fast Ethernet).
	* Perform "Stress Testing" on a variety of network infrastructure, network devices and security solutions in place.
	* Simulate "Distributed Denial-of-Service" & "Denial-of-Service" attacks, validating Firewall rules, Router ACLs, Intrusion Detection System and Intrusion Prevention System policies.

The main differentiator of the T50 is that it is able to send all protocols, sequentially, using one single SOCKET, besides it is capable to be used to modify network routes, letting IT Security Professionals performing advanced "Penetration Test".

##HOW TO INSTALL

```bash
  $ make
  $ sudo make install
```

##COMPILE OPTIONS

Define environment variable DEBUG before compiling if you don't want full optimizations to take place and symbols linked on executable.

Define USE_ANSI if you want some colorized texts, using ANSI CSI escape codes.

Example:

```bash
$ USE_ANSI=1 make
```

##CHECKING TARBALL AUTHENTICITY

I will attach a signature file for T50 tarballs on SourceForge.

To get my public key with GPG:

```bash
$ gpg --recv-keys fredericopissarra@gmail.com
```

Here, my actual public key fingerprint:

```
pub   4096R/C09C2054 2016-10-06 [expires: 2019-10-06]
      Key fingerprint = 11A5 2C9C E02A 24AA EBFC  046B 20AA 0246 C09C 2054
uid                  Frederico Lamberti Pissarra <fredericopissarra@gmail.com>
sub   4096R/F9AA8B75 2016-10-06 [expires: 2019-10-06]
```

After downloading the tar.gz file (f.i, t50-5.8.tar.gz), get the .asc file as well. To verify if the tarball is authentic, just type the following command:

```bash
$ gpg --verify t50-5.8.tar.gz.asc t50-5.8.tar.gz
gpg: Signature made Qua 25 Abr 2018 16:46:52 -03 using RSA key ID C09C2054
gpg: Good signature from "Frederico Lamberti Pissarra <fredericopissarra@gmail.com>"
```
