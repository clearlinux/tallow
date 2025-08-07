## DISCONTINUATION OF PROJECT. 

This project will no longer be maintained by Intel. 

Intel will not provide or guarantee development of or support for this project, including but not limited to, maintenance, bug fixes, new releases or updates. Patches to this project are no longer accepted by Intel. If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the community, please create your own fork of the project.

Contact: webadmin@linux.intel.com  

tallow
======

Tallow is a fail2ban/lard replacement that uses systemd's native
journal API to scan for attempted ssh logins, and issues temporary
IP bans for clients that violate certain login patterns.

Author: Auke Kok <auke-jan.h.kok@intel.com>


How it works
============

Tallow attaches to the journal and subscribes to messages from
/usr/sbin/sshd. The messages are matched against rules and the IP
address is extracted from the message.  For each IP address that is
extracted, the last timestamp and count is kept. Once the count exceeds
a threshold, the offending IP address is added to an ipset and blocked 
with a corresponding firewall rule. It will use firewalld or 
iptables / ip6tables.

The timestamp is kept for pruning. Records are pruned from the list
if the IP address hasn't been seen by tallow for longer than the
threshold. If the IP was blocked and the threshold was exceeded,
the IP is unblocked. If the threshold was never reached, the record
is removed as well.

Pruning is done automatically after incoming messages are processed,
so there is a chance that if no messages arrive, that IP addresses
remain blocked for longer than the default blocking period.



Motivation
==========

This program was originally written to demonstrate the journal API. One
of the typical use cases for journal (or syslog) readers was to act
dynamically on certain syslog messages, and many types of actions
can be imagined. This is trivial to implement on systems that use
the journal API, and often doesn't take much code at all.

The journal is attached to and forwarder to the end. We place a
simple message filter, and then process each incoming message. For
more information check out the sd-journal manual pages, which contain
example code that demonstrates almost the exact same code flow.



Security
========

DISCLAIMER: THIS IS NOT A SECURITY APPLICATION !!!

Tallow is meant to reduce log clutter and system resource usage at
the cost of denying access to potentially valid users.

Even if you reduce the threshold at which clients are blocked to 1,
an attacker may still gain access to your server if the attacker uses
the correct credentials.

By itself, tallow is an application that creates a Denial
of Service. It's sole purpose and function is to block IP
addresses. Therefore, with tallow running on a service, you could
potentially deny valid users access to your systems if you deploy
tallow.

Be very careful if you deploy tallow on systems that expect valid
users to log on from many random source addresses. If your user
mistypes their username, they could find themselves denied access.