import os
import sys
import json
import hpfeeds
from ConfigParser import ConfigParser
import processors
from cifsdk.client.http import HTTP as Client
import logging

logging.basicConfig(level=logging.DEBUG)

def handle_message(msg, host, token, provider, tlp, confidence, tags, group, verify_ssl):
    indicator = msg['src_ip']
    data = {"indicator": indicator,
            "tlp": tlp,
            "confidence": confidence,
            "tags": tags,
            "provider": provider,
            "group": group}
    logging.debug('Initializing Client instance with: {0}, {1}, {2}'.format(token, host, verify_ssl))
    cli = Client(token=token,
                 remote=host,
                 verify_ssl=verify_ssl)
    logging.debug('Submitting indicator: {0}'.format(data))
    cli.indicators_create(json.dumps(data))
    logging.debug('Indicator submitted')
    return


def parse_config(config_file):
    if not os.path.isfile(config_file):
        sys.exit("Could not find configuration file: {0}".format(config_file))

    parser = ConfigParser()
    parser.read(config_file)

    config = {}

    config['hpf_feeds'] = parser.get('hpfeeds', 'channels').split(',')
    config['hpf_ident'] = parser.get('hpfeeds', 'ident')
    config['hpf_secret'] = parser.get('hpfeeds', 'secret')
    config['hpf_port'] = parser.getint('hpfeeds', 'hp_port')
    config['hpf_host'] = parser.get('hpfeeds', 'hp_host')

    config['cif_token'] = parser.get('cifv3', 'cif_token')
    config['cif_host'] = parser.get('cifv3', 'cif_host')
    config['cif_provider'] = parser.get('cifv3', 'cif_provider')
    config['cif_tlp'] = parser.get('cifv3', 'cif_tlp')
    config['cif_confidence'] = parser.get('cifv3', 'cif_confidence')
    config['cif_tags'] = parser.get('cifv3', 'cif_tags')
    config['cif_group'] = parser.get('cifv3', 'cif_group')
    config['cif_verify_ssl'] = parser.getboolean('cifv3', 'cif_verify_ssl')

    logging.debug('Parsed config: {0}'.format(repr(config)))
    return config


def main():
    if len(sys.argv) < 2:
        return 1

    config = parse_config(sys.argv[1])
    host = config['hpf_host']
    port = config['hpf_port']
    channels = [c.encode('utf-8') for c in config['hpf_feeds']]
    ident = config['hpf_ident'].encode('utf-8')
    secret = config['hpf_secret'].encode('utf-8')
    cif_token = config['cif_token']
    cif_host = config['cif_host']
    cif_provider = config['cif_provider']
    cif_tlp = config['cif_tlp']
    cif_confidence = config['cif_confidence']
    cif_tags = config['cif_tags']
    cif_group = config['cif_group']
    cif_verify_ssl = config['cif_verify_ssl']

    processor = processors.HpfeedsMessageProcessor()
    logging.debug('Initializing HPFeeds connection with {0}, {1}, {2}, {3}'.format(host,port,ident,secret))
    try:
        hpc = hpfeeds.new(host, port, ident, secret)
    except hpfeeds.FeedException, e:
        logging.error('Experienced FeedException: {0}'.format(repr(e)))
        return 1

    def on_message(identifier, channel, payload):
        for msg in processor.process(identifier, channel, payload, ignore_errors=True):
            handle_message(msg, cif_host, cif_token, cif_provider, cif_tlp, cif_confidence, cif_tags, cif_group, cif_verify_ssl)

    def on_error(payload):
        sys.stderr.write("Handling error.")
        hpc.stop()

    hpc.subscribe(channels)
    try:
        hpc.run(on_message, on_error)
    except:
        pass
    finally:
        hpc.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
