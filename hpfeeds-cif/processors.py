import json
import traceback
from urllib.parse import urlparse
import socket
import hashlib
import re
from IPy import IP
import logging

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s][%(threadName)s] - %(message)s'
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

IPV6_REGEX = re.compile(r'::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


def computeHashes(data, record):
    data = data.encode('utf-8')
    m = hashlib.md5()
    m.update(data)
    record['md5'] = m.hexdigest()

    m = hashlib.sha1()
    m.update(data)
    record['sha1'] = m.hexdigest()

    m = hashlib.sha256()
    m.update(data)
    record['sha256'] = m.hexdigest()

    m = hashlib.sha512()
    m.update(data)
    record['sha512'] = m.hexdigest()


def clean_ip(ip):
    if not ip:
        return ip
    mat = IPV6_REGEX.search(ip)
    if mat:
        return mat.group(1)
    return ip


class ezdict(object):
    def __init__(self, d):
        self.d = d

    def __getattr__(self, name):
        return self.d.get(name, None)

    def __getitem__(self, name):
        return self.d.get(name, None)


def geo_intel(maxmind_geo, maxmind_asn, ip, prefix=''):
    result = {
        'city': None,
        'region_name': None,
        'region': None,
        'area_code': None,
        'time_zone': None,
        'longitude': None,
        'metro_code': None,
        'country_code3': None,
        'latitude': None,
        'postal_code': None,
        'dma_code': None,
        'country_code': None,
        'country_name': None,
        'org': None
    }

    if maxmind_geo:
        geo = maxmind_geo.record_by_addr(ip)
        if geo:
            if geo['city'] is not None:
                geo['city'] = geo['city'].decode('latin1')
            result.update(geo)

    if maxmind_asn:
        org = maxmind_asn.org_by_addr(ip)
        if org:
            result['org'] = org.decode('latin-1')
    if prefix:
        result = dict((prefix+name, value) for name, value in result.items())
    return result


def create_message(event_type, identifier, src_ip, dst_ip,
                   src_port=None, dst_port=None, transport='tcp', protocol='ip', vendor_product=None,
                   direction=None, ids_type=None, severity=None, signature=None, app=None, **kwargs):

    msg = dict(kwargs)
    msg.update({
        'type':   event_type,
        'sensor': identifier,
        'src_ip': clean_ip(src_ip),
        'dest_ip': clean_ip(dst_ip),
        'src_port': src_port,
        'dest_port': dst_port,
        'transport': transport,
        'protocol': protocol,
        'vendor_product': vendor_product,
        'direction': direction,
        'ids_type': ids_type,
        'severity': severity,
        'signature': signature,
        'app': app,
    })
    return msg


def glastopf_event(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing glastopf event')
        traceback.print_exc()
        return None

    if dec.pattern == 'unknown':
        return None

    request_url = None
    try:
        # from mnemosyne...
        if 'Host' in dec['request']['header'] and not dec['request']['url'].startswith('http'):
            request_url = 'http://' + dec['request']['header']['Host'] + dec['request']['url']
        else:
            # best of luck!
            request_url = dec['request']['url']
    except:
        logger.warning('exception processing glastopf url, ignoring')
        traceback.print_exc()

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'glastopf.events',
        identifier,
        tags=tags,
        src_ip=dec.source[0],
        src_port=dec.source[1],
        dst_ip=None,
        dst_port=80,
        vendor_product='Glastopf',
        app='glastopf',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
        request_url=request_url,
    )


def dionaea_capture(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing dionaea event')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'dionaea.capture',
        identifier,
        tags=tags,
        src_ip=dec.saddr,
        dst_ip=dec.daddr,
        src_port=dec.sport,
        dst_port=dec.dport,
        vendor_product='Dionaea',
        app='dionaea',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='File downloaded on Honeypot',
        url=dec.url,
        md5=dec.md5,
        sha512=dec.sha512,
    )


def dionaea_connections(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing dionaea connection')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'dionaea.connections',
        identifier,
        tags=tags,
        src_ip=dec.remote_host,
        dst_ip=dec.local_host,
        src_port=dec.remote_port,
        dst_port=dec.local_port,
        vendor_product='Dionaea',
        app='dionaea',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
        dionaea_action=dec.connection_type,
    )


def beeswarm_hive(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing beeswarm.hive event')
        traceback.print_exc()
        return
    return create_message(
        'beeswarm.hive',
        identifier,
        src_ip=dec.attacker_ip,
        dst_ip=dec.honey_ip,
        src_port=dec.attacker_source_port,
        dst_port=dec.honey_port,
        vendor_product='Beeswarm',
        app='beeswarm',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
    )


def kippo_sessions(identifier, payload):
    return kippo_cowrie_sessions(identifier, payload, 'Kippo', 'kippo.sessions')


def cowrie_sessions(identifier, payload):
    return kippo_cowrie_sessions(identifier, payload, 'Cowrie', 'cowrie.sessions')


def kippo_cowrie_sessions(identifier, payload, name, channel):
    name_lower = name.lower()
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing {} event'.format(name_lower))
        logger.warning(traceback.print_exc())
        return

    messages = []

    tags = []
    if dec['tags']:
        tags = dec['tags']

    base_message = create_message(
        channel,
        identifier,
        tags=tags,
        src_ip=dec.peerIP,
        dst_ip=dec.hostIP,
        src_port=dec.peerPort,
        dst_port=dec.hostPort,
        vendor_product=name,
        app=name_lower,
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
        ssh_version=dec.version
    )

    messages.append(base_message)

    if dec.credentials:
        for username, password in dec.credentials:
            msg = dict(base_message)
            msg['signature'] = 'SSH login attempted on Honeypot'
            msg['ssh_username'] = username
            msg['ssh_password'] = password
            messages.append(msg)

    if dec.urls:
        for url in dec.urls:
            msg = dict(base_message)
            msg['signature'] = 'URL download attempted on Honeypot'
            msg['url'] = url
            messages.append(msg)

    if dec.commands:
        for command in dec.commands:
            msg = dict(base_message)
            msg['signature'] = 'command attempted on Honeypot'
            msg['command'] = command
            messages.append(msg)

    if dec.unknownCommands:
        for command in dec.unknownCommands:
            msg = dict(base_message)
            msg['signature'] = 'unknown command attempted on Honeypot'
            msg['command'] = command
            messages.append(msg)

    if dec.hashes:
        for fhash in dec.hashes:
            msg = dict(base_message)
            msg['signature'] = 'File downloaded on Honeypot'
            msg['hash'] = fhash
            msg['sha256'] = fhash
            messages.append(msg)

    return messages


def conpot_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
        remote = dec.remote[0]
        remote_port = dec.remote[1]
        if dec.local[1]:
            local_port = dec.local[1]
        else:
            local_port = 0

        # http asks locally for snmp with remote ip = "127.0.0.1"
        if remote == "127.0.0.1":
            return
    except:
        logger.warning('exception processing conpot event')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'conpot.events-'+dec.data_type,
        identifier,
        tags=tags,
        src_ip=remote,
        dst_ip=dec.public_ip,
        src_port=remote_port,
        dst_port=local_port,
        vendor_product='Conpot',
        app='conpot',
        direction='inbound',
        ids_type='network',
        severity='medium',
        signature='Connection to Honeypot',
    )


def snort_alerts(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing snort alert')
        traceback.print_exc()
        return None

    # extra snort fields
    kwargs = {}
    for field in ['header', 'classification', 'priority']:
        kwargs['snort_{}'.format(field)] = dec[field]

    return create_message(
        'snort.alerts',
        identifier,
        src_ip=dec.source_ip,
        dst_ip=dec.destination_ip,
        src_port=dec.source_port,
        dst_port=dec.destination_port,
        transport=dec.protocol,
        vendor_product='Snort',
        app='snort',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature=dec.signature,
        ip_id=dec.id,
        ip_ttl=dec.ttl,
        ip_len=dec.iplen,
        ip_tos=dec.tos,
        eth_src=dec.ethsrc,
        eth_dst=dec.ethdst,
        tcp_len=dec.tcplen,
        tcp_flags=dec.tcpflags,
        udp_len=dec.udplength,
        **kwargs
    )


def suricata_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing suricata event')
        traceback.print_exc()
        return None

    # extra suricata fields
    kwargs = {}
    for field in ['action', 'signature_id', 'signature_rev']:
        kwargs['suricata_{}'.format(field)] = dec.get(field)

    return create_message(
        'suricata.events',
        identifier,
        src_ip=dec.source_ip,
        dst_ip=dec.destination_ip,
        src_port=dec.source_port,
        dst_port=dec.destination_port,
        transport=dec.protocol,
        vendor_product='Suricata',
        app='suricata',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature=dec.signature,
        ip_id=dec.ip_id,
        ip_ttl=dec.ip_ttl,
        ip_tos=dec.ip_tos,
        eth_src=dec.eth_src,
        eth_dst=dec.eth_dst,
        tcp_len=dec.tcp_len,
        tcp_flags=dec.tcp_flags,
        udp_len=dec.udp_len,
        **kwargs
    )


def p0f_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing suricata event')
        traceback.print_exc()
        return None
    return create_message(
        'p0f.events',
        identifier,
        src_ip=dec.client_ip,
        dst_ip=dec.server_ip,
        src_port=dec.client_port,
        dst_port=dec.server_port,
        vendor_product='p0f',
        app='p0f',
        direction='inbound',
        ids_type='network',
        severity='informational',
        signature='Packet Observed by p0f',
        p0f_app=dec.app,
        p0f_link=dec.link,
        p0f_os=dec.os,
        p0f_uptime=dec.uptime,
    )


def amun_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing amun event')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'amun.events',
        identifier,
        tags=tags,
        src_ip=dec.attackerIP,
        dst_ip=dec.victimIP,
        src_port=dec.attackerPort,
        dst_port=dec.victimPort,
        vendor_product='Amun',
        app='amun',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
    )


def wordpot_event(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warn('exception processing wordpot alert')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'wordpot.alerts',
        identifier,
        tags=tags,
        src_ip=dec.source_ip,
        dst_ip=dec.dest_ip,
        src_port=dec.source_port,
        dst_port=dec.dest_port,
        vendor_product='Wordpot',
        app='wordpot',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
        request_url=dec.url,
    )


def shockpot_event(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing shockpot alert')
        traceback.print_exc()
        return None

    kwargs = {}
    if dec.command_data:
        computeHashes(dec.command_data, kwargs)

    if dec.command:
        m = re.search('(?P<url>https?://[^\s;]+)', dec.command)
        if m:
            kwargs.update(m.groupdict())

    try:
        p = urlparse(dec.url)
        host = p.netloc.split(':')[0]
        socket.inet_aton(host)
        dest_ip = host
    except:
        dest_ip = None

    if dec.url:
        kwargs['request_url'] = dec.url

    return create_message(
        'shockpot.events',
        identifier,
        src_ip=dec.source_ip,
        dst_ip=dest_ip,
        src_port=0,
        dst_port=dec.dest_port,
        vendor_product='ThreatStream Shockpot',
        app='shockpot',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
        **kwargs
    )


def elastichoney_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing elastichoney alert')
        traceback.print_exc()
        return

    if dec.type == 'attack':
        severity = 'high'
        signature = 'ElasticSearch Exploit Attempted'
    else:
        severity = 'medium'
        signature = 'Connection to Honeypot'

    user_agent = ''
    if dec.headers:
        user_agent = dec.headers.get('user_agent', '')

    kwargs = {}
    if dec.payloadBinary:
        computeHashes(dec.payloadBinary.decode('base64'), kwargs)

    if dec.payloadResource:
        kwargs['url'] = dec.payloadResource

        if dec.payloadCommand:
            kwargs['command'] = '{} {}'.format(dec.payloadCommand, dec.payloadResource)

    return create_message(
        'elastichoney.events',
        identifier,
        src_ip=dec.source,
        dst_ip=dec.honeypot,
        src_port=0,
        dst_port=9200,
        vendor_product='ElasticHoney',
        app='elastichoney',
        direction='inbound',
        ids_type='network',
        severity=severity,
        signature=signature,
        elastichoney_form=dec.form,
        elastichoney_payload=dec.payload,
        user_agent=user_agent,
        request_url=dec.url,
        **kwargs
    )


def rdphoney_sessions(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing amun event')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'rdphoney.sessions',
        identifier,
        tags=tags,
        src_ip=dec.peerIP,
        dst_ip=dec.hostIP,
        src_port=dec.peerPort,
        dst_port=dec.hostPort,
        vendor_product='RDPHoney',
        app='rdphoney',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
        username=dec.username,
        data=dec.data
    )


def uhp_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing amun event')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'uhp.events',
        identifier,
        tags=tags,
        src_ip=dec.src_ip,
        dst_ip=dec.dst_ip,
        src_port=dec.src_port,
        dst_port=dec.dst_port,
        vendor_product='UHP',
        app=dec.app,
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
        action=dec.action,
        message=dec.message
    )


def elasticpot_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing elasticpot event')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    return create_message(
        'elasticpot.events',
        identifier,
        tags=tags,
        src_ip=dec.src_ip,
        dst_ip=dec.dst_ip,
        src_port=dec.src_port,
        dst_port=dec.dst_port,
        vendor_product='elasticpot',
        app='elasticpot',
        direction="inbound",
        ids_type='network',
        severity='high',
        signature='Connection to honeypot',
        eventid=dec.eventid,
        message=dec.message,
        url=dec.url,
        request=dec.request,
        user_agent=dec.user_agent
    )

def ssh_auth_logger_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing ssh-auth-logger event')
        traceback.print_exc()
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    base_message = create_message(
        'ssh-auth-logger',
        identifier,
        tags=tags,
        src_ip=dec.src,
        dst_ip=dec.dst,
        src_port=dec.spt,
        dst_port=dec.dpt,
        vendor_product='ssh-auth-logger',
        app='ssh-auth-logger',
        direction='inbound',
        ids_type='network',
        severity='high',
        signature='Connection to Honeypot',
        ssh_username=dec.duser
    )

    if dec.fingerprint:
        base_message['ssh_fingerprint'] = dec.fingerprint
        base_message['keytype'] = dec.keytype
        base_message['signature'] = 'SSH login attempted on ssh-auth-logger honeypot with key'
    elif dec.password:
        base_message['ssh_password'] = dec.password
        base_message['signature'] = 'SSH login attempted on ssh-auth-logger honeypot with password'


    return base_message

def honeydb_agent_events(identifier, payload):
    try:
        dec = ezdict(json.loads(str(payload)))
    except:
        logger.warning('exception processing honeydb-agent event')
        traceback.print_exc()
        return

    if dec.event == 'TX':
        # Ignore server responses to attackers
        logger.debug('Ignoring honeydb-agent response to attacker message')
        return

    tags = []
    if dec['tags']:
        tags = dec['tags']

    base_message = create_message(
        'honeydb-agent',
        identifier,
        tags=tags,
        src_ip=dec.remote_host,
        dst_ip=dec.local_host,
        src_port=dec.remote_port,
        dst_port=dec.local_port,
        vendor_product='honeydb-agent',
        app='honeydb-agent',
        direction='inbound',
        ids_type='network',
        severity='high',
        service=dec.service,
        bytes=dec.bytes,
        signature='Connection to Honeypot'
    )

    if dec.data:
        try:
            data = bytes.fromhex(dec.data).decode('utf8')
            base_message['data'] = data
        except Exception as e:
            logger.warning('Failed to hex-decode data in honeydb-agent log: data: {} exceptiom: {}'.format(dec.data,e))

    return base_message

PROCESSORS = {
    'amun.events': [amun_events],
    'glastopf.events': [glastopf_event],
    'dionaea.capture': [dionaea_capture],
    'dionaea.connections': [dionaea_connections],
    'beeswarm.hive': [beeswarm_hive],
    'kippo.sessions': [kippo_sessions],
    'cowrie.sessions': [cowrie_sessions],
    'conpot.events': [conpot_events],
    'snort.alerts': [snort_alerts],
    'wordpot.events': [wordpot_event],
    'shockpot.events': [shockpot_event],
    'p0f.events': [p0f_events],
    'suricata.events': [suricata_events],
    'elastichoney.events': [elastichoney_events],
    'rdphoney.sessions': [rdphoney_sessions],
    'uhp.events': [uhp_events],
    'elasticpot.events': [elasticpot_events],
    'ssh-auth-logger.events': [ssh_auth_logger_events],
    'honeydb-agent.events': [honeydb_agent_events]
}


class HpfeedsMessageProcessor(object):
    def __init__(self, maxmind_geo_file=None, maxmind_asn_file=None, ignore_cidr_list=list()):
        self.maxmind_geo = None
        self.maxmind_asn = None
        self.ignore_cidr_list=ignore_cidr_list

    def is_ignore_addr(self,ip):
        try:
            checkip = IP(ip)
            for c in self.ignore_cidr_list:
                if checkip in c:
                    return True
            return False
        except ValueError as e:
            logger.warning('Received invalid IP via hpfeeds: {}'.format(e))
            return True

    def geo_intelligence_enrichment(self, messages):
        for message in messages:
            src_geo = geo_intel(self.maxmind_geo, self.maxmind_asn, message.get('src_ip'), prefix='src_')
            message.update(src_geo)
            dst_geo = geo_intel(self.maxmind_geo, self.maxmind_asn, message.get('dest_ip'), prefix='dest_')
            message.update(dst_geo)

    def process(self, identifier, channel, payload, ignore_errors=False):
        procs = PROCESSORS.get(channel, [])
        results = []
        for processor in procs:
            if ignore_errors:
                try:
                    message = processor(identifier, payload)
                except:
                    continue
            else:
                message = processor(identifier, payload)

            if message:
                if isinstance(message, list):
                    for msg in message:
                        src_ip = msg.get('src_ip')
                        if self.is_ignore_addr(src_ip):
                            logger.debug('Ignored submission for {}: ignore_cidr_list: {}'.format(src_ip,self.ignore_cidr_list))
                            continue
                        else:
                            results.append(msg)
                else:
                    src_ip = message.get('src_ip')
                    if self.is_ignore_addr(src_ip):
                        logger.debug('Ignored submission for {}: ignore_cidr_list: {}'.format(src_ip, self.ignore_cidr_list))
                        continue
                    else:
                        results.append(message)

        if self.maxmind_geo or self.maxmind_asn:
            self.geo_intelligence_enrichment(results)
        return results
