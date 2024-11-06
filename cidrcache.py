#! /usr/bin/python3

import redis
from logging import getLogger
from ipaddress import ip_network, ip_address
from threading import Lock

class CIDRCache:
    def __init__(self, khost, kport):
        self._logSys = getLogger("fail2ban.a.%s" % self.__class__.__name__)
        self._logSys.info("CIDRCache constructor")
        self.redis = redis.Redis(host=khost, port=kport, db=0, decode_responses=True)
        self._lock = Lock()
        self.cidrs = []
        self._logSys.info("CIDRCache initialising")
        for k in self.redis.scan_iter(match="cidr:*"):
            self._add(k)

    def _add(self, key):
        try:
            network = ip_network(key[5:])
            self.cidrs.append((network, key))
        except ValueError:
            self._logSys.warning(f"cannot convert {key} to an IPv46Network")

    def add(self, key):
        with self._lock:
            self._add(key)

    def len(self):
        return len(self.cidrs)

    def check(self,ip):
        # ip should already be an IPv46Address
        for net, key in self.cidrs:
            if ip in net:
                self._logSys.info(f"found {str(ip)} in net {key}")
                try:
                    # this WILL raise an exception, because of the automatic
                    # decode setting in the constructor. Instead of setting up
                    # a second channel to KV store, catch the exception and 
                    # use the raw data contained therein
                    data = self.redis.get(key)
                except UnicodeDecodeError as e:
                    data = e.object
                return data
        return None

# instantiate a global object, to share the cache between jails
CIDRS = CIDRCache("192.168.30.1", 6379)

