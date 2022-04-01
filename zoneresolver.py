# -*- coding: utf-8 -*-

import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dnslog.settings")
import django
django.setup()
import copy
import re
import json
import requests
import struct
import socket
import random
from dnslib import RR, QTYPE, RCODE, TXT, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
from logview.models import *
from dnslog import settings


class MySQLLogger:
    def __init__(self):
        pass

    def log_data(self, dnsobj):
        pass

    def log_error(self, handler, e):
        pass

    def log_pass(self, *args):
        pass

    def log_prefix(self, handler):
        pass

    def log_recv(self, handler, data):
        pass

    def log_reply(self, handler, reply):
        pass

    def log_request(self, handler, request):
        if QTYPE[request.q.qtype] == 'AAAA':
            return
        domain = request.q.qname.__str__().lower()
        if not domain.endswith(settings.DNS_DOMAIN + '.'):
            return 
        matches = re.search(r'\.?([^\.]+)\.%s\.' % settings.DNS_DOMAIN, domain)
        if not matches:
            return
        user = User.objects.filter(user_domain__exact=matches.group(1))
        if not user and domain.strip(".") != settings.ADMIN_DOMAIN:
            user = User.objects.filter(user_domain__exact='@')
        if not user:
            return
        ip = handler.client_address[0]
        try:
            doc = requests.get('http://ip.ws.126.net/ipquery?ip=%s' % ip).text
            doc = doc[doc.find('var localAddress=')+17:].strip()
            doc = doc.replace('city', '"city"').replace('province', '"province"')
            _doc = json.loads(doc)
            city = _doc['province'] + ' ' + _doc['city']
        except Exception as e:
            city = ''
        log = DNSLog(user=user[0], host=domain.strip('.'), type=QTYPE[request.q.qtype], ip=ip, city=city)
        log.save()

    def log_send(self, handler, data):
        pass

    def log_truncated(self, handler, reply):
        pass


class ZoneResolver(BaseResolver):
    """
        Simple fixed zone file resolver.
    """

    def __init__(self, zone, glob=False):
        """
            Initialise resolver from zone file.
            Stores RRs as a list of (label,type,rr) tuples
            If 'glob' is True use glob match against zone file
        """
        self.zone = [(rr.rname, QTYPE[rr.rtype], rr) for rr in RR.fromZone(zone)]
        self.glob = glob
        self.eq = 'matchGlob' if glob else '__eq__'

    def resolve(self, request, handler):
        """
            Respond to DNS request - parameters are request packet & handler.
            Method is expected to return DNS response
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        if qtype == 'TXT':
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT('Nothing to response')))
        # rebind
        try:
            if qtype == 'A' and qname.__str__().endswith(settings.DNS_DOMAIN + '.'):
                subs = qname.__str__().replace('.' + settings.DNS_DOMAIN + '.', '')
                ret = subs.split('.')
                if len(ret) == 4 and ret[-2].lower() == 'r':
                    valid_ip = int(ret[0], 16)
                    invalid_ip = int(ret[1], 16)
                    valid_ip = socket.inet_ntoa(struct.pack("!I", valid_ip))
                    invalid_ip = socket.inet_ntoa(struct.pack("!I", invalid_ip))
                    ip = random.choice((valid_ip, invalid_ip))
                    rr = RR(qname, request.q.qtype, rdata=A(ip), ttl=0)
                    reply.add_answer(rr)
                    return reply
        except Exception as e:
            pass
        #
        for name, rtype, rr in self.zone:
            # Check if label & type match
            if getattr(qname, self.eq)(name) and (qtype == rtype or qtype == 'ANY' or rtype == 'CNAME'):
                # If we have a glob match fix reply label
                if self.glob:
                    a = copy.copy(rr)
                    a.rname = qname
                    if qname.__str__().rstrip('.') in settings.ADMIN_DOMAIN:
                        a.ttl = 1200
                    reply.add_answer(a)
                else:
                    reply.add_answer(rr)
                # Check for A/AAAA records associated with reply and
                # add in additional section
                if rtype in ['CNAME', 'NS', 'MX', 'PTR']:
                    for a_name, a_rtype, a_rr in self.zone:
                        if a_name == rr.rdata.label and a_rtype in ['A', 'AAAA']:
                            reply.add_ar(a_rr)
        if not reply.rr:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


def main():
    zone = '''
{dns_domain}.       IN      NS      {ns1_domain}.
{dns_domain}.       IN      NS      {ns2_domain}.
*.{dns_domain}.       IN      NS      {ns1_domain}.
*.{dns_domain}.       IN      NS      {ns2_domain}.
*.{dns_domain}.       IN      A       {server_ip}
{dns_domain}.         IN      A       {server_ip}
'''.format(
        dns_domain=settings.DNS_DOMAIN,
        ns1_domain=settings.NS1_DOMAIN,
        ns2_domain=settings.NS2_DOMAIN,
        server_ip=settings.SERVER_IP
    )
    resolver = ZoneResolver(zone, True)
    logger = MySQLLogger()
    udp_server = DNSServer(resolver, port=53, address='', logger=logger)
    udp_server.start()
    print("Zone Resolver started (%s:%d) [%s]" % ("*", 53, "UDP"))


if __name__ == '__main__':
    main()
