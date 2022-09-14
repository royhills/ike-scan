# ike-scan

[![Build](https://github.com/royhills/ike-scan/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/royhills/ike-scan/actions/workflows/c-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/royhills/ike-scan/badge.svg?branch=master)](https://coveralls.io/github/royhills/ike-scan?branch=master)

Discover and fingerprint IKE hosts (IPsec VPN Servers)

## Table of Contents  
- [Building and Installing](#building-and-installing)  
- [Overview](#overview)  
- [Usage](#usage)
- [Implementation Details](#implementation-details)
  - [Host Input and Memory Requirements](#host-input-and-memory-requirements)
  - [Rate Limiting](#rate-limiting)
  - [Cookie Generation and Remote Host Identification](#cookie-generation-and-remote-host-identification)
  - [IKE Packet Details](#ike-packet-details)
  - [Backoff Fingerprinting](#backoff-fingerprinting)
- [Program Output](#program-output)
- [Examples](#examples)
- [Supported Platforms](#supported-platforms)
- [Further Reading and RFCs](#further-reading-and-rfcs)
- [Contact Information](#contact-information)

## Building and Installing

ike-scan uses the standard GNU autoconf and automake tools, so installation
is the normal process:

- Run ```git clone https://github.com/royhills/ike-scan.git``` to obtain the project source code
- Run ```cd ike-scan``` to enter source directory
- Run ```autoreconf --install``` to generate a viable ./configure file
- Run ```./configure``` or ```./configure --with-openssl``` to use the OpenSSL libraries
- Run ```make``` to build the project
- Run ```make check``` to verify that everything works as expected
- Run ```make install``` to install (you'll need root or sudo for this part)

If you plan on performing pre-shared key cracking, then you should configure ike-scan to use the OpenSSL hash functions rather than its built-in functions because the OpenSSL ones are normally faster.  To do this, make sure you have the OpenSSL include files and libraries installed, and run configure as ```./configure --with-openssl```.  Whether you use OpenSSL or not won't affect the functionality of ike-scan, just the speed of pre-shared
key cracking with psk-crack.

Some operating systems install the OpenSSL headers and libraries by default; others require that you install an optional package, for example on Debian Linux you need to install the libssl-dev package.  Alternatively, you can download and install the OpenSSL tarball from http://www.openssl.org/

It should build on most modern Unix-like OSes.  It works on Windows with Cygwin and can be used as a standalone Windows executable when cygwin1.dll is present.

If you are using the Windows-32 binary package, please also read the file README-WIN32 which details the differences when running on the Windows
platform.

The program is known to build and run on Linux, FreeBSD, OpenBSD, NetBSD, Win32/Cygwin, Solaris, MacOS X, HP Tru64, HP-UX, and SCO OpenServer.  For more details see the section "SUPPORTED PLATFORMS" below.

## Overview

ike-scan discovers IKE hosts and can also fingerprint them using the
retransmission backoff pattern.

ike-scan can perform the following functions:

- **Discovery** Determine which hosts in a given IP range are running IKE.  This is done by displaying those hosts which respond to the IKE requests sent by ike-scan.
- **Fingerprinting** Determine which IKE implementation the hosts are using, and in some cases determine the version of software that they are running.  This is done in two ways: firstly by UDP backoff fingerprinting which involves recording the times of the IKE response packets from the target hosts and comparing the observed retransmission backoff pattern against known patterns; and secondly by Vendor ID fingerprinting which compares Vendor ID payloads from the VPN servers against known vendor id patterns.
- **Transform Enumeration** Find which transform attributes are supported by the VPN server for IKE Phase-1 (e.g. encryption algorithm, hash algorithm etc.).
- **User Enumeration** For some VPN systems, discover valid VPN usernames.
- **Pre-Shared Key Cracking** Perform offline dictionary or brute-force password cracking for IKE Aggressive Mode with Pre-Shared Key authentication. This uses ike-scan to obtain the hash and other parameters, and psk-crack (which is part of the ike-scan package) to perform the cracking.

The retransmission backoff fingerprinting concept is discussed in more detail in the UDP backoff fingerprinting paper which should be included in the ike-scan kit as [UDP Backoff Fingerprinting Paper](udp-backoff-fingerprinting-paper.txt).

The program sends IKE phase-1 (Main Mode or Aggressive Mode) requests to the specified hosts and displays any responses that are received.  It handles retry and retransmission with backoff to cope with packet loss.  It also limits the amount of bandwidth used by the outbound IKE packets.

IKE is the Internet Key Exchange protocol which is the key exchange and authentication mechanism used by IPsec.  Just about all modern VPN systems implement IPsec, and the vast majority of IPsec VPNs use IKE for key exchange. Main Mode is one of the modes defined for phase-1 of the IKE exchange (the other defined mode is aggressive mode).  RFC 2409 section 5 specifies that main mode must be implemented, therefore all IKE implementations can be expected to support main mode. Many also support Aggressive Mode.

## Usage

To see current usage information, run the ike-scan binary like so:

```ike-scan -h```

Additional documentation is provided on the [NTA Monitor Wiki](http://www.royhills.co.uk/wiki/index.php/Ike-scan_Documentation)

To report bugs or suggest new features, please [create a GitHub issue](https://github.com/royhills/ike-scan/issues/new).

## Implementation Details

### Host Input and Memory Requirements

The hosts to scan can be specified on the command line or read from an input file using the ```--file=<fn>``` option.  The program can cope with large numbers of hosts limited only by the amount of memory needed to store the list of host_entry structures.  Each host_entry structure requires 45 bytes on a 32-bit system, so a class B network (65534 hosts) would require about 2.8 MB for the list.  The hosts can be specified as either IP addresses or hostnames, however the program will store all hosts internally as IP addresses and will only display IP addresses in the output (ike-scan calls gethostbyname(3) to determine the IP address of each host, but this can be disabled with the ```--nodns``` option).

### Rate Limiting

The program limits the rate at which it sends IKE packets to ensure that it does not overload the network connection.  By default it uses an outbound data rate of 56000 bits per second.  This can be changed with the ```--bandwidth``` option.

If you want to send packets at a specific rate, you can use the ```--interval``` option.

### Cookie Generation and Remote Host Identification

ike-scan generates unique IKE cookies for each host, and it uses these cookies to determine which host the response packets belong to.  Note that it does not rely on the source IP address of the response packets because it is possible for a response packet to be sent from a different IP address than it was originally sent to.  See the PROGRAM OUTPUT section for an example of this.

The cookies are generated by taking the first 64 bits of an MD5 hash of the current time in seconds and microseconds as returned by gettimeofday(), the unique host number, and the host IP address.  This ensures that the cookies are unique with a reasonable degree of certainty.

If ```--verbose``` is in effect, any packets that are received with cookies that do not match will result in a message like:

```Ignoring 84 bytes from 172.16.2.2 with unknown cookie 195c837e5a39f657```

If ```--verbose``` is not in effect, such packets are silently ignored.

This type of cookie mismatch may be caused by:

- The host is still returning IKE responses to a previous ike-scan run;
- The packet is not an IKE packet or has been corrupted somehow; or
- An IKE packet which is nothing to do with ike-scan has been received.

### IKE Packet Details

The main mode packets sent contain an ISAKMP header and an SA payload.  The SA payload contains a single proposal, and the proposal can contain a variable number of transforms as detailed below.

By default, the SA proposal contains 8 transforms.  These 8 transforms represent all possible combinations of:

- Encryption Algorithm: DES-CBC and 3DES-CBC;
- Hash Algorithm: MD5 and SHA-1; and
- DH Group: 1 (MODP 768) and 2 (MODP 1024).

An example tcpdump output of the main mode packet sent by ike-scan using the default transform set is shown below.  This shows the 8 transforms and also shows the order in which they are sent:

    16:57:16.024536 192.168.124.8.500 > 172.16.2.2.500:  [udp sum ok]isakmp 1.0 msgid 00000000: phase 1 I ident:
      (sa: doi=ipsec situation=identity
        (p: #1 protoid=isakmp transform=8
          (t: #1 id=ike (type=enc value=3des)(type=hash value=sha1)(type=auth value=preshared)(type=group desc value=modp1024)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080))
          (t: #2 id=ike (type=enc value=3des)(type=hash value=md5)(type=auth value=preshared)(type=group desc value=modp1024)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080))
          (t: #3 id=ike (type=enc value=1des)(type=hash value=sha1)(type=auth value=preshared)(type=group desc value=modp1024)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080))
          (t: #4 id=ike (type=enc value=1des)(type=hash value=md5)(type=auth value=preshared)(type=group desc value=modp1024)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080))
          (t: #5 id=ike (type=enc value=3des)(type=hash value=sha1)(type=auth value=preshared)(type=group desc value=modp768)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080))
          (t: #6 id=ike (type=enc value=3des)(type=hash value=md5)(type=auth value=preshared)(type=group desc value=modp768)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080))
          (t: #7 id=ike (type=enc value=1des)(type=hash value=sha1)(type=auth value=preshared)(type=group desc value=modp768)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080))
          (t: #8 id=ike (type=enc value=1des)(type=hash value=md5)(type=auth value=preshared)(type=group desc value=modp768)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080)))) (DF) (ttl 64, id 0, len 364)```

This default transform set is designed to be acceptable to most IKE implementations - most will accept at least one of the offered transforms. However, it is sometimes necessary to use a different authentication method (pre-shared key is the most common, but is not always supported), and occasionally it is necessary to specify a different cipher such as 256-bit AES. More rarely it may be necessary to change the lifetime.  Finally, some implementations require a specific "Vendor ID" string to be sent by the client before they will respond.  This can be specified with the ```--vendor``` option.

The default transform set results in a packet data length of 336 bytes which when IP and UDP headers are added gives a total packet size of 364 bytes.

It is possible to specify the Authentication Method with ```--auth``` (default is 1 - pre-shared key) and the IKE lifetime in seconds with ```--lifetime``` (default is 28800 seconds or 8 hours as recommended by RFC 2407). If you specify ```--lifetime``` as 0, then no lifetime attribute is included in the transform payloads.  If you are specifying custom transforms, you can you can use this option more than once to produce transform payloads with different lifetimes.  Each ```--trans``` option will use the previously specified lifetime value.

It is possible to specify a custom transform set with ```--trans=e[/l],h,a,g``` where "e" is the Encryption Algorithm, "l" is the key length for variable length ciphers, "h" is the Hash Algorithm, "a" is the Authentication Method and g is the DH Group.  These are specified as numeric values; see RFC 2409 Appendix A for details of which values to use.

For example: ```--trans=5,2,1,2``` specifies:
```Enc=5 (3DES-CBC), Hash=2 (SHA1), Auth=1 (shared key), DH Group=2 (modp 1024)```

and ```--trans=7/256,1,1,5``` specifies:
```Enc=7 (AES), Keylen=256 bits, Hash=MD5, Auth=shared key, DH Group=5 (modp 1536)```

You can use the ```--trans``` option more than once to send an arbitrary number of custom transforms in the proposal.

Specifying a custom transform set overrides any authentication method specified with ```--auth```.  However, it still uses the lifetime value specified in the last ```--lifetime``` option.

An example of a complex custom transform set is:

```--trans=5,2,1,2 --lifetime=0 --trans=7/256,1,3,5 --lifetime=600 --trans=7/128,1,3,5```

This would specify the following three transforms:

- 3DES Encryption with SHA1 hash, shared key authentication, DH group 2, and the default lifetime;
- 256-bit AES Encryption with MD5 hash, RSA authentication, DH group 5, and no lifetime; and
- 128-bit AES Encryption with MD5 hash, RSA authentication, DH group 5, and lifetime of 600 second.

If a custom transform set is specified, the packet length will differ from the default.  Fewer than 8 transforms will make it smaller, and more than 8 transforms will make it larger.  If the packet size exceeds the MTU, then it will be fragmented.  You may need to increase the ```--interval``` setting for large packets to avoid overloading your network connection.  Some VPN servers may ignore very long packets.

A custom transform can be useful in the following situations:

- If none of the transforms in the default transform set is acceptable to the remote IKE implementation;
- If you know that a particular transform will be acceptable, and you want to minimise bandwidth use or allow faster scanning rates; or
- If you want to determine exactly which transforms a remote IKE implementation supports for fingerprinting.

The default mode used is Main Mode.  However, it is possible to specify Aggressive Mode with the ```--aggressive``` option.  When this is done, three additional payloads will be included: Key Exchange, Nonce and ID.  This will increase the packet size, and you may need to increase ```--interval``` to ensure that ike-scan doesn't try to use too much bandwidth as a result.  If you use Aggressive Mode, you can also use the following options:

- ```--id```            Set identification value.
- ```--idtype```        Set identification type (Default 3 (ID_USER_FQDN)).
- ```--dhgroup```       Specify Diffie-Hellman group (Default 2 - MODP 1024).

If you use Aggressive Mode, then you can only use one Diffie Hellman group in the transform set.  If you specify custom transforms with the ```--trans``` option, you should ensure that they all use the same group, and that this group matches the DH group specified with the ```--dhgroup``` option, or the default of 2 if ```--dhgroup``` is not specified.

IKE hosts may respond in one of two ways:

- With an IKE main or aggressive mode response packet containing the cookie that was originally sent to the host.  This is a "handshake" response and indicates that the host supports IKE and finds our proposal acceptable; or
- With an IKE notify message containing the cookie that was originally sent to the host.  This is a "notify" response and indicates that the host is running IKE, but does not accept our proposal.

An example tcpdump output for a "handshake" response is:

    16:57:48.068698 172.16.2.2.500 > 192.168.124.8.500:  [udp sum ok]isakmp 1.0 msgid 00000000: phase 1 R ident:
      (sa: doi=ipsec situation=identity
        (p: #1 protoid=isakmp transform=1
          (t: #1 id=ike (type=enc value=3des)(type=hash value=sha1)(type=auth value=preshared)(type=group desc value=modp1024)(type=lifetype value=sec)(type=lifeduration len=4 value=00007080)))) (ttl 126, id 37891, len 112)

This shows that the IKE host has responded with an ISAKMP header and an SA payload containing a single proposal.  This proposal contains a single transform representing the transform chosen from the proposal sent by ike-scan.

An example tcpdump output for a "notify" response is:

    17:12:55.038554 192.168.89.22.500 > 192.168.37.1.500:  [udp sum ok]isakmp 1.0 msgid 00000000: phase 1 R inf:
      (n: doi=0 proto=1 type=NO-PROPOSAL-CHOSEN) (ttl 52, id 39577, len 68)

This shows that the IKE host has responded with an ISAKMP header and a notify payload.  The notify payload is an informational message with the type "NO-PROPOSAL-CHOSEN".

ike-scan does not respond to any of the IKE responses it receives, so the IKE main mode handshake will never complete.  Some IKE implementations do not log handshakes that don't complete; these implementations will not log the scanning and therefore the owners of these systems will not be aware of the scanning.  It is possible to use ike-scan to determine if a given implementation will log these scanning attempts if you have access to the system logs.

### Backoff Fingerprinting

For those hosts that respond, ike-scan records the times of the received IKE responses.  The backoff between IKE responses varies between different IKE implementations and can therefore be used as a fingerprint.  The ```--showbackoff``` option is used to display the backoff times for each host which responded.  Note that using the ```--showbackoff``` option will cause ike-scan to wait for 60 seconds after the last received packet to ensure that it has seen all of the responses.  This 60 second wait can be altered by specifying a different value in seconds to the ```--showbackoff``` option.

When all of the packets have been received, the backoff table is displayed, and the program attempts to match the backoff pattern against the known backoff patterns contained in the text file [ike-backoff-patterns](ike-backoff-patterns).  It is possible to add new patterns to this file.

Note that only hosts which respond with a handshake can be fingerprinted by backoff timings; hosts which respond with a notify message cannot.  This is because notify messages are only ever sent once and are not subject to retransmission with backoff.

If you discover IKE hosts with backoff patterns which are not recognised by ike-scan, then you are encouraged to submit the pattern and details of the IKE implementation to me so I can incorporate it into future versions of ike-scan.  You can do this by opening an issue, or a pull request on github.

Note that any packet loss will prevent the backoff fingerprinting from working because the program needs to see all of the responses.

ike-scan can also be used to fingerprint IKE hosts in other ways.  For example:

- Some systems (such as Checkpoint Firewall-1) allow the use of any source port (e.g. ```--sport=0```) whereas others (e.g. Windows 2000) only respond to IKE requests from source port 500 (actually, Windows 2000 responds to requests from any port, but always sends the responses back to port 500 which amounts to the same thing).
- Some systems use proprietary notify message codes which allows them to be identified.  For example, Checkpoint Firewall-1 4.0, 4.1 and NG Base use notify message code 9101.  ike-scan recognises this and will identify the system as "Checkpoint Firewall-1 4.x or NG Base".
- Different systems support different transforms, and this support can be determined by trying all possible combinations with ```--trans```. Note however, that the user can usually change the transform set, so this cannot be relied upon by itself.
- Different implementations require different IKE Lifetimes.  Some implementations will accept any lifetime, whereas others will only accept lifetimes below a certain value.
- By using another tool (e.g. tcpdump) to sniff the returned IKE packets, the IP ID and IP TTL can be determined.  These can be useful in fingerprinting the IP stack which can help to determine the IKE implementation.
- The IKE host may send Vendor ID payloads which uniquely identify the implementation.  This Vendor ID fingerprinting method was first proposed by Brett Eldridge <beldridg@pobox.com>.  ike-scan will display any vendor ID payloads that it receives, and will attempt to match these against known Vendor ID patterns.

### Program Output

The program output consists of two sections:

- The IKE host detection section; and
- The IKE backoff pattern section (if ```--showbackoff``` is specified).

The IKE host detection section contains one line for each host that responds.  The response can either be a successful handshake or an informational message.  Only the first packet returned by any given host is displayed in this section.

Some examples of the IKE host detection section are:

    10.0.1.98        IKE Handshake returned (1 transforms)
    10.0.1.22        Notify message 14 (NO-PROPOSAL-CHOSEN)
    10.0.1.189        (10.0.1.130) Notify message 9101 (No common authentication method with Firewall.)

In the above example output, host 10.0.1.98 has returned an IKE handshake, 10.0.1.22 has returned notify message 14 (decimal) which corresponds to the RFC-defined error message "NO-PROPOSAL-CHOSEN" (see RFC 2408 section 3.14.1), and 10.0.1.189 has returned a non-standard notify message 9101 but the response has come from the IP address 10.0.1.130 rather than the address which the request was sent to (presumably this is a multi-homed system).  Notify message 9101 is not defined by RFC 2408, but it is known to be a Checkpoint proprietary notify code (therefore the system is probably Firewall-1) and the program displays the text included in the notify message.

Some examples of the IKE backoff pattern section are:

    IP Address      No.     Recv time               Delta Time
    172.16.2.2      1       1042549209.247980       0.000000
    172.16.2.2      2       1042549211.239254       1.991274
    172.16.2.2      3       1042549213.241935       2.002681
    172.16.2.2      4       1042549215.244731       2.002796
    172.16.2.2      5       1042549217.247512       2.002781
    172.16.2.2      6       1042549219.250254       2.002742
    172.16.2.2      7       1042549221.253044       2.002790
    172.16.2.2      8       1042549225.258551       4.005507
    172.16.2.2      9       1042549229.264074       4.005523
    172.16.2.2      10      1042549233.269605       4.005531
    172.16.2.2      11      1042549237.275145       4.005540
    172.16.2.2      12      1042549241.280654       4.005509
    172.16.2.2      Implementation guess: Firewall-1 4.1/NG

    IP Address      No.     Recv time               Delta Time
    10.0.1.98        1       1042549209.426540       0.000000
    10.0.1.98        2       1042549224.425435       14.998895
    10.0.1.98        3       1042549239.422251       14.996816
    10.0.1.98        Implementation guess: Cisco IOS / PIX

Here, host 172.16.2.2 returned a total of 12 packets and the pattern matched "Firewall-1 4.1/NG", and host 10.0.1.98 returned 3 packets matching the pattern for "Cisco IOS / PIX".  The recv time column shows the absolute time when the packet was received in seconds and microseconds since the epoch; delta time shows the elapsed time between packets in seconds and microseconds.

## Examples

The below example will run IKE detection against the single host 172.16.2.2. No backoff fingerprinting will be done, and all options (timeouts, retrys, transform set Etc) will be the default.

- ```ike-scan 172.16.2.2```

This will read the target hosts from the file "hostlist.txt".

- ```ike-scan --file=hostlist.txt```

This reads the hosts from stdin and performs both IKE detection and backoff fingerprinting.  The backoff wait is specified as 20 seconds.

- ```cat hostlist.txt | ike-scan --file=- --showbackoff=20```

This will run ike-scan against all hosts in the network specified by 172.16.0.0/16 (including network and broadcast addresses).  In this case, this will result in a total of 65536 hosts being scanned - from 172.16.0.0 to 172.16.255.255 inclusive.

- ```ike-scan 172.16.0.0/16```

This uses the range notation to scan a total of 65536 hosts from 172.16.0.0 to 172.16.255.255 inclusive.

- ```ike-scan 172.16.0.0-172.16.255.255```

## Supported Platforms

ike-scan has been built and tested on the following platforms:

- Debian Linux 1.3.1 on IA32 with gcc 2.7.2.1, libc5 and 2.0.29 Kernel
- Debian Linux 2.2r7 (Potato) on IA32 with gcc 2.95.2 and 2.2.17 Kernel
- Debian Linux 3.0r1 (Woody) on IA32 with gcc 2.95.4 and 2.4.18 Kernel
- Debian Linux 3.1 (Sarge) on IA32 with gcc 3.3.4 and 2.4.27 Kernel
- Debian Linux 3.0 (Woody) on PA-RISC with gcc 3.0.4 and 2.4.17-64 Kernel
- Debian Linux 3.0 (Woody) on Alpha with gcc 3.3.1 and 2.4.18-smp Kernel
- Redhat Advanced Server 3.2 on IA64 with gcc 3.2.3 and 2.4.21-19.EL Kernel
- HP-UX 11.11 on PA-RISC with gcc 3.4.1
- HP-UX 11.11 on PA-RISC with HP cc HP92453-01 B.11.11.32003.GP
- FreeBSD 4.3 on IA32 with gcc 2.95.3
- OpenBSD 3.1 on IA32 with gcc 2.95.3
- NetBSD 1.6 on IA32 with gcc 2.95.3
- SCO OpenServer 5.0.7 on IA32 with gcc 2.95.3
- Windows NT 4.0 / Cygwin 1.5.12 on IA32 with gcc 3.3.3
- Solaris 2.8 on SPARC with gcc 2.95.3
- HP Tru64 Unix v5.1 on Alpha with Tru64 cc
- MacOS X (Darwin 7.7.0) on PowerPC

I've also had reports that it builds OK on the following systems:

- RedHat Linux 7.1 with 2.4 Kernel
- RedHat Linux 8.0 with 2.4 Kernel
- Debian Linux 3.1 on Alpha
- Debian Linux 3.1 on ARM
- Debian Linux 3.1 on HP PA-RISC
- Debian Linux 3.1 on Intel IA64
- Debian Linux 3.1 on Motorola 68000
- Debian Linux 3.1 on MIPS
- Debian Linux 3.1 on PowerPC
- Debian Linux 3.1 on IBM S390
- Debian Linux 3.1 on SPARC

It should work, or be capable of working, on any Unix-like system which has a 64-bit integer type, supports sockets and has the system calls malloc, gethostbyname, gettimeofday, inet_ntoa, memset, select, socket, and strerror.

If you port ike-scan to a system not listed above, please let me know the details of the changes required so I can add them to future releases.

## Further Reading and RFCs

For an in-depth coverage of IPsec including IKE, I recommend the book "IPsec The New Security Standard for the Internet, Intranets and Virtual Private Networks" by Doraswamy and Harkins, ISBN 0-13-011898-2.  I used this book together with the RFCs to learn about IKE.

The following RFCs relate to IKE:

- RFC 2407  The Internet IP Security Domain of Interpretation for ISAKMP
- RFC 2408  Internet Security Association and Key Management Protocol (ISAKMP)
- RFC 2409  The Internet Key Exchange (IKE)
- RFC 2412  The OAKLEY Key Determination Protocol
- RFC 5996  Internet Key Exchange Protocol Version 2 (IKEv2)

All of these RFCs can be obtained from: http://www.ietf.org/rfc

## Contact Information

The best way to contact me is via the ike-scan repository on github.

I would like to hear from you if you have any of the following:

- A modern Unix-like OS which ike-scan won't build on;
- An OS not listed in the list above which ike-scan builds and runs OK on;
- Any IKE implementation patterns that are not already in the ike-backoff-patterns file.
  - Please include details of the pattern and also details of the IKE implementation;
- Any Vendor ID pattern that is not already in the ike-vendor-ids file; or
- Any comments or suggestions about the program.

If you need to contact me offline, please email me at ike-scan@nta-monitor.com
