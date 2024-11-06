# Record fail2ban bans in a KV store

## Motivation

My server gets constantly attacked. I previously used `action_mw` to get emails with
the whois details of each ban. But that proved just too much in the meantime, even though
my bantime is now one year. Yes - offenders get blocked for one year.


## Action

I wrote two modules, the `cidrcache.py` module instantiates a global object, that holds
all known CIDR networks for the IP addresses of past offenders. These records hold
`pickle`d whois data structures and get refreshed only if they are older than 14 days.
I am even considering to make this a month or so. I am mostly interested in the countrycode
of the offender.

The second module is the action, that gets called when a ban occurs. For each ban I create
a unique id. A KV hash holds the details of the ban, like jailname, date/time, IP, country code.
This UUID is then referenced in several sets for IP, jail, country and day.

This makes it easy and fast to get the data about the distribution of offenders and the bans
per day etc.

