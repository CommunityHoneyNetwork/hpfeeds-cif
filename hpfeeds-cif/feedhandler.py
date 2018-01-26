import os
import sys
import json
import hpfeeds
from ConfigParser import ConfigParser
import processors
from cifsdk.client.http import HTTP as Client


def handle_message(msg, host, token, provider):
    indicator = msg['src_ip']
    data = {"indicator": indicator,
            "tlp": "amber",
            "confidence": "8",
            "tags": "honeypot",
            "provider": provider,
            "group": "everyone"}
    cli = Client(token=token,
                 remote=host,
                 verify_ssl=False)
    cli.indicators_create(json.dumps(data))


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

    processor = processors.HpfeedsMessageProcessor()

    try:
        hpc = hpfeeds.new(host, port, ident, secret)
    except hpfeeds.FeedException, e:
        return 1

    def on_message(identifier, channel, payload):
        sys.stderr.write("Handling message.")
        for msg in processor.process(identifier, channel, payload, ignore_errors=True):
            handle_message(msg, cif_host, cif_token, cif_provider)

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
