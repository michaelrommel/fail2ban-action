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

## Installation

In order to get all the modules needed for this installed correctly and not clobbering
the global environment, I decided to install fail2ban from source and have all things
started from a python virtual environment. These were the steps if I remember correctly...

```console
# make a copy of the configuration files in /etc/fail2ban
apt-get purge fail2ban
apt install libsystemd-dev liblz1 python3-pyinotify python3-systemd whois
apt install python3.11-venv

python3 -mvenv .venv
source .venv/bin/activate
pip3 install ipwhois
pip3 install redis
pip3 install dnspython
pip3 install systemd-python
pip3 install nanoid

git clone https://github.com/fail2ban/fail2ban.git
cd fail2ban
python setup.py install

cp ./build/fail2ban.service /root/.venv/bin/
```

## Configuration

List of files:
- /etc/fail2ban/jail.d/raven.conf
- /etc/fail2ban/actions.d/storeinredis.py
- /etc/fail2ban/actions.d/cidrcache.py

``` console 
- systemctl enable /root/.venv/bin/fail2ban.service
- systemctl start fail2ban.service
```
