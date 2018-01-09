
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

`whitelist`=`<ip address|pattern>`
Specify an IP address or `pattern` that should never be
blocked. Multiple IP addresses can be included by repeating the
`whitelist` option several times. By default, only 127.0.0.1 is
whitelisted.

If the last character of the listed ip adress is a `.` or a `:`, then
the matching is only performed on the leftmost characters of an IP
address against the whitelist entry. For instance, if you whitelist
`10.` then all IP addresses in the `10/8` subnet mask will match this
whitelist entry and never be blocked.

`ipv6`=`<0|1>`
Enable of disable ipv6 (ip6tables) support. Ipv6 is disabled
automatically on systems that do not appear to have ipv6 support
and enabled when ipv6 is present. Use this option to explicitly
disable ipv6 support if your system does not have ipv6 or is
missing ip6tables. Even with ipv6 disabled, tallow will track
and log ipv6 addresses.

`nocreate`=`<0|1>`
Disable the creation of iptables rules and ipset sets. By default,
tallow will create new iptables(1) and ip6tables(1) rules when needed
automatically. If set to `1`, `tallow(1)` will not create any new
iptables rules or ipset sets to work. You should create them manually
before tallow starts up and remove them afterwards. To create them
manually, you can use the following commands:

  ```
  iptables -t filter -I INPUT -m set --match-set tallow src -j DROP
  ipset create tallow hash:ip family inet timeout 3600

  ip6tables -t filter -I INPUT -m set --match-set tallow6 src -j DROP
  ipset create tallow6 hash:ip family inet6 timeout 3600
  ```

## SEE ALSO

tallow(1)

## AUTHOR

Auke Kok <auke-jan.h.kok@intel.com>

