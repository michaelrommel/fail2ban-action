#! /usr/bin/python3
import sys
import redis

from logging import getLogger
from fail2ban.server.action import ActionBase
from pickle import loads, dumps
from ipwhois import IPWhois
from datetime import datetime, date, timezone, timedelta
from nanoid import generate
from ipaddress import ip_network, ip_address

# not sure how this can be improved...
sys.path.append("/etc/fail2ban/action.d")

from cidrcache import CIDRS

class WhoisCache:
    def __init__(self, redis):
        self._logSys = getLogger("fail2ban.a.%s" % self.__class__.__name__)
        self._logSys.info("initializing WhoisCache")
        self.redis = redis
        self.cidrs = CIDRS

    def _get_ipwhois(self):
        whois = None
        try:
            whois = IPWhois(self.ip).lookup_rdap(depth=1, retry_count=1, rate_limit_timeout=1)
            whois["updated"] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception as e:
            self._logSys.error(f"could not get whois info for {self.ip}")
            self._logSys.error(f"Exception: {e=}")

        return whois

    def _get(self):
        ret = self.cidrs.check(ip_address(self.ip))
        return loads(ret) if ret else ret

    def set(self, ip):
        self.ip = ip
        existing_data = self._get()
        ccode = None
        updated = 0

        if existing_data is not None:
            updated = existing_data.get('updated')
            ccode = existing_data.get("asn_country_code")
            existing_updated = datetime.strptime(updated, '%Y-%m-%dT%H:%M:%SZ')

        if (existing_data is None or
            existing_updated < (datetime.utcnow() - timedelta(days=14))):
            self._logSys.info(f"getting whois data for {self.ip}")
            whois = self._get_ipwhois()
            if whois:
                ccode = whois.get("asn_country_code")
                cidr = whois.get("asn_cidr")
                if cidr == "NA":
                    try:
                        cidr = whois["network"]["cidr"]
                    except:
                        pass
                self.redis.set(f"cidr:{cidr}", dumps(whois))
                self.cidrs.add(f"cidr:{cidr}")
                self._logSys.info(f"updated cidr: {cidr}")
            else:
                self._logSys.warning(f"no info for {self.ip}")
                ccode = None
        else:
            # for helper scripts this is showing that the CIDR range was already known
            ccode = ccode.lower()

        return ccode


class StoreInRedis(ActionBase):
    def __init__(self, jail, name, matches=None):
        self._logSys = getLogger("fail2ban.a.%s" % self.__class__.__name__)
        self._logSys.info(f"initializing StoreInRedis for {jail}")
        self.khost = "192.168.30.1"
        self.kport = 6379
        self.jail = jail
        self.name = name
        self.matches = matches
        self.norestored = 1
        self.r = redis.Redis(host=self.khost, port=self.kport, db=0, decode_responses=True)
        self.cache = WhoisCache(self.r)

    def start(self):
        pass

    def stop(self):
        pass

    def ban(self, aInfo):
        now = datetime.now(tz=timezone(timedelta(hours=1)))
        nowstamp = int(now.timestamp())
        today = now.date().isoformat()
        ip = str(aInfo.get("ip"))
        self._logSys.info(f"banning ip {ip}")
        self._logSys.info(f"CIDR Cache has {CIDRS.len()} entries")
        ccode = self.cache.set(ip)
        if ccode is None:
            self._logSys.warning(f"{self.jail} no info for {self.ip}")
            ccode = "XX"
        ccode = ccode.upper()
        nid = generate("0123456789abcdefghijklmnopqrstuvwxyz", 10)
        # to count the numbers of banned IPs per Country
        self.r.sadd(f"f2b:{ccode}", nid)
        # to count the numbers of banned IPs per jail
        self.r.sadd(f"f2b:{self.jail.name}", nid)
        # to count the numbers of bans per day
        self.r.sadd(f"f2b:{today}", nid)
        # to record all occurrences of this ip
        self.r.sadd(f"f2b:{ip}", nid)
        # to record details of the ban
        self.r.hset(f"f2b:{nid}", items=["jail", self.jail.name, "ip", ip, "country", ccode, "timestamp", nowstamp])

    def flush(self):
        return True

    def unban(self, aInfo):
        ip = str(aInfo.get("ip"))
        self._logSys.info(f"unbanning ip {ip}")
        ccode = self.cache.set(ip)
        if ccode is None:
            self._logSys.warning(f"{self.jail} unban no info for {ip}")
            ccode = "XX"
        ccode = ccode.upper()
        for nid in self.r.smembers(f"f2b:{ip}"):
            self.r.srem(f"f2b:{ccode}", nid)
            self.r.srem(f"f2b:{self.jail.name}", nid)
            self.r.delete(f"f2b:{nid}")
        self.r.delete(f"f2b:{ip}")

Action = StoreInRedis
