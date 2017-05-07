
## tallow.conf

The tallow configuration file

## NAME

tallow.conf - Tallow daemon configuration file

## SYNOPSIS

`/etc/tallow.conf`

## DESCRIPTION

This file is read on startup by the tallow(1) daemon, and can
be used to provide options to the tallow daemon. If not present,
tallow will operate with built-in defaults.

## OPTIONS

`ipt_path`=`<string>`
Specifies the location of the ipset(1), iptables(1) or ip6tables(1)
program. By default, tallow will look in "/usr/sbin" for them.

`expires`=`<int>`
The number of seconds that IP addresses are blocked for. Note that
due to the implementation, IP addresses may be blocked for much
longer than this period. If IP addresses are seen, but not
blocked within this period, they are also removed from the
watch list. Defaults to 3600s.

`threshold`=`<int>`
Specifies the number of times an IP address may appear before it
is blocked. Defaults to 3.

`whitelist`=`<ipv4 address>`
Specify an IP address that should never be blocked. Multiple IP
addresses can be included by repeating the `whitelist`
option several times. By default, only 127.0.0.1 is whitelisted.

`ipv6`=`<0|1>`
Enable of disable ipv6 (ip6tables) support. Ipv6 is disabled
automatically on systems that do not appear to have ipv6 support
and enabled when ipv6 is present. Use this option to explicitly
disable ipv6 support if your system does not have ipv6 or is
missing ip6tables. Even with ipv6 disabled, tallow will track
and log ipv6 addresses.

## SEE ALSO

tallow(1), iptables(1)

## AUTHOR

Auke Kok <auke-jan.h.kok@intel.com>

