# -*- coding: utf-8 -*-
import logging
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dnslog.settings")
import django
django.setup()
import copy
import re
import struct
import socket
import random
from dnslib import RR, QTYPE, RCODE, TXT, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
from logview.models import *
from dnslog import settings
import queue
import threading
from django.db import close_old_connections
from django.utils import timezone


q_query = queue.Queue()
logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
                    filename='dns_server.log', filemode='a')


def process_log():
    global q_query
    while True:
        try:
            user_domain, ip, domain, qtype, timestamp = q_query.get()
            user = User.objects.filter(user_domain__exact=user_domain)
            # 有需要也可以记录下不属于任何用戶的请求记录
            # 你需要创建1个用户，然后把他的 user_domain 更新为 @
            # if not user and domain.strip(".") != settings.ADMIN_DOMAIN:
            #     user = User.objects.filter(user_domain__exact='@')
            if not user:
                logger.error('No such user: %s' % str(e), exc_info=True)

            # 由于顺序获取客户端的IP地理位置过于耗时，大约300ms，不再顺序获取
            # try:
            #     doc = requests.get('https://whois.pconline.com.cn/ip.jsp?ip=%s' % ip, timeout=10.0).text.strip()
            #     city = doc.split(' ')[0]
            # except Exception as e:
            #     city = ''

            city = ''
            try:
                sub_name = domain.split('.')[-3-len(settings.DNS_DOMAIN.split('.'))]
            except:
                sub_name = ''
            for _ in range(5):
                try:
                    log = DNSLog(user=user[0], host=domain.strip('.'), sub_name=sub_name, type=QTYPE[qtype], ip=ip,
                                 city=city, created_time=timestamp)
                    log.save()
                    break
                except django.db.utils.OperationalError as e:
                    logger.error('process_log.exception.1: %s' % str(e), exc_info=True)
                    close_old_connections()
                except Exception as e:
                    logger.error('process_log.exception.2: %s' % str(e), exc_info=True)
        except django.db.utils.OperationalError as e:
            close_old_connections()
            logger.error('process_log.exception.3: %s' % str(e), exc_info=True)
        except Exception as e:
            logger.error('process_log.exception.4: %s' % str(e))


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
        global q_query
        if QTYPE[request.q.qtype] == 'AAAA':
            return
        domain = request.q.qname.__str__().lower()
        if not domain.endswith(settings.DNS_DOMAIN + '.'):
            return 
        matches = re.search(r'\.?([^\.]+)\.%s\.' % settings.DNS_DOMAIN, domain)
        if not matches:
            return
        user_domain = matches.group(1)
        ip = handler.client_address[0]
        qtype = request.q.qtype
        item = (user_domain, ip, domain, qtype, timezone.now())
        q_query.put(item)

    def log_send(self, handler, data):
        pass

    def log_truncated(self, handler, reply):
        pass


class ZoneResolver(BaseResolver):
    def __init__(self, zone, glob=False):
        self.zone = [(rr.rname, QTYPE[rr.rtype], rr) for rr in RR.fromZone(zone)]
        self.glob = glob
        self.eq = 'matchGlob' if glob else '__eq__'

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        if qtype == 'TXT':
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT('Nothing to response')))
        # DNS rebind
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
            logger.error('DNS rebind resolve.exception: %s' % str(e), exc_info=True)
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
*.{dns_domain}.       IN      AAAA       2408:871a:2100:3:0:ff:b025:348d
{dns_domain}.         IN      AAAA       2408:871a:2100:3:0:ff:b025:348d
'''.format(
        dns_domain=settings.DNS_DOMAIN,
        ns1_domain=settings.NS1_DOMAIN,
        ns2_domain=settings.NS2_DOMAIN,
        server_ip=settings.SERVER_IP
    )
    resolver = ZoneResolver(zone, True)
    threading.Thread(target=process_log).start()
    udp_server = DNSServer(resolver, port=53, address='', logger=MySQLLogger())
    udp_server.start()
    logger.info("Zone Resolver started (%s:%d) [%s]" % ("*", 53, "UDP"))


if __name__ == '__main__':
    main()
