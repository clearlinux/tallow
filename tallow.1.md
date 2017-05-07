
## tallow 

Reduce log clutter due to ssh login attempts.

## SYNOPSIS

`/usr/sbin/tallow`

## DESCRIPTION

`tallow` is a daemon that watches the systemd journal for
messages from the `sshd` service. It parses the messages
and looks for attempted random logins such as failed logins to the
root account and failed logins to invalid user accounts.

If such logins were detected, the offending IP address is stored
in a list. Items from this list are regularly purged, but if
the amount of times that a specific IP address is seen exceeds
a threshold (default 3), an iptables(1) rule is inserted in the
`TALLOW` chain in the `filter` netfilter table. The
rule will match all packets from the IP address and `DROP`
them.

The system administrator needs to assure that all incoming packets
are routed through the `TALLOW` chain by inserting a rule
appropriately, e.g. `iptables -I INPUT -j TALLOW`. The `TALLOW`
chain may have to be created manually first with e.g. `iptables -N
TALLOW`.

Care should be taken to assure that legitimate users are not
blocked inadvertently. You may wish to list any valid IP address
with the whitelist option in tallow.conf(5). Multiple addresses
can be whitelisted.

## OPTIONS

The `tallow` daemon itself has no runtime configuration. All
configuration is done through the tallow.conf(5) config file.

## SEE ALSO

systemd-journald(1), iptables(1), tallow.conf(5)

## BUGS

`tallow` is `NOT A SECURITY SOLUTION`, nor does it protect
against random password logins. A attacker may still be able to
logon to your systems if you allow password logins.

## AUTHOR

Auke Kok <auke-jan.h.kok@intel.com>
